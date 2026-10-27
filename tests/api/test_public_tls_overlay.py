"""`public_tls` is seed-only, and overlay candidates are held to the public-mode rules.

Which public-mode load-time rules an overlay can reach:

* Rule 3 (every served name is a DNS name inside a zone): an overlay can add a resource or
  alias, so it is reachable. 422 here.
* Rule 5 (every served name matches exactly one certificate): same, reachable. 422 here.
* Rules 1, 2, 4 and the shape of `public_tls` itself: startup-only. They constrain the
  seed's `public_tls` and `ca` blocks, and an overlay can set neither (the top-level key
  allowlist refuses both before any validation runs), so they are asserted at startup in
  `tests/configmodel/test_public_tls_seed.py` and by the allowlist tests below.
* Rule 6 (file paths under `/config/public-tls/`): enforced where the files are read.
"""

import dataclasses
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml
from fastapi import HTTPException
from pydantic import SecretStr

from gwops.api.app import create_app
from gwops.api.routes_state import _OVERLAY_ALLOWED_TOP_KEYS, _reject_forbidden_overlay_keys
from tests.public_tls_support import (
    ZONE,
    k8s,
    public_cert,
    public_seed,
    ssh,
    tls_block,
    webapp,
)

from .conftest import ADMIN_TOKEN, DepsBundle, make_deps

_AUTOMATION_TOKEN = "automation-token"

_ACME_BLOCK: dict[str, Any] = {
    "email": "ops@example.com",
    "accept_tos": True,
    "directory": "production",
    "token_file": "/config/acme/cloudflare-token",
}
_ACME_CERT: dict[str, Any] = {
    "name": "issued",
    "names": [f"*.apps.{ZONE}"],
    "source": "acme",
}
_ACME_PATCHES = [
    pytest.param({"public_tls": {"acme": _ACME_BLOCK}}, id="acme-block"),
    pytest.param({"public_tls": {"acme": {"directory": "production"}}}, id="directory-only"),
    pytest.param(
        {"public_tls": {"acme": {"token_file": "/config/acme/other-token"}}}, id="token-file-only"
    ),
    pytest.param({"public_tls": {"acme": {"propagation": "authoritative"}}}, id="propagation-only"),
    pytest.param({"public_tls": {"acme": None}}, id="null-acme"),
    pytest.param({"public_tls": {"certificates": [_ACME_CERT]}}, id="source-acme-certificate"),
    pytest.param(
        {"public_tls": {"certificates": [{"name": "wildcard", "source": "acme"}]}},
        id="source-acme-replacing-a-file-certificate",
    ),
    pytest.param(
        {"public_tls": tls_block(certificates=[_ACME_CERT], acme=_ACME_BLOCK)},
        id="whole-block-with-acme",
    ),
    pytest.param(
        {
            "public_tls": tls_block(
                certificates=[public_cert("wildcard", source="acme")], acme=_ACME_BLOCK
            )
        },
        id="whole-block-source-acme-default-name",
    ),
]

_TWO_CERTS = tls_block(
    certificates=[
        public_cert("wildcard", [f"*.{ZONE}"]),
        public_cert("api-specific", [f"api.{ZONE}"]),
    ]
)


def _seed(**top: Any) -> str:
    base: dict[str, Any] = {"ssh_upstreams": [ssh("host1", f"host1.{ZONE}:22")]}
    base.update(top)
    return yaml.safe_dump(public_seed(_TWO_CERTS, **base), sort_keys=False)


def _client(bundle: DepsBundle, token: str) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(bundle.deps)),
        base_url="http://gwops",
        headers={"Authorization": f"Bearer {token}"},
    )


@pytest.fixture
def public_bundle(tmp_path: Path) -> DepsBundle:
    """A seed in public mode; no private CAs exist (there is no `ca.x509` in public mode)."""
    return make_deps(tmp_path, seed=_seed(), ensure_cas=False)


@pytest.fixture
async def admin(public_bundle: DepsBundle) -> AsyncIterator[httpx.AsyncClient]:
    async with _client(public_bundle, ADMIN_TOKEN) as client:
        yield client


@pytest.fixture
async def automation(public_bundle: DepsBundle) -> AsyncIterator[httpx.AsyncClient]:
    settings = public_bundle.deps.settings.model_copy(
        update={"gwops_automation_token": SecretStr(_AUTOMATION_TOKEN)}
    )
    public_bundle.deps = dataclasses.replace(public_bundle.deps, settings=settings)
    async with _client(public_bundle, _AUTOMATION_TOKEN) as client:
        yield client


def _assert_nothing_changed(bundle: DepsBundle) -> None:
    assert bundle.store.list() == []
    assert bundle.reconciler.triggers == []


class TestPublicTlsIsSeedOnly:
    def test_public_tls_is_not_an_overlay_top_level_key(self) -> None:
        """Pins the allowlist: nothing under `public_tls` is overlay-writable."""
        assert "public_tls" not in _OVERLAY_ALLOWED_TOP_KEYS

    @pytest.mark.parametrize(
        "patch",
        [
            pytest.param({"public_tls": tls_block()}, id="whole-block"),
            pytest.param({"public_tls": {"zones": ["evil.example"]}}, id="zones-only"),
            pytest.param(
                {"public_tls": {"certificates": [public_cert("evil", ["*.evil.example"])]}},
                id="certificates-only",
            ),
            pytest.param({"public_tls": None}, id="null-to-switch-the-mode-off"),
            pytest.param({"public_tls": {}}, id="empty"),
        ],
    )
    async def test_an_overlay_setting_public_tls_is_422_and_persists_nothing(
        self, admin: httpx.AsyncClient, public_bundle: DepsBundle, patch: dict[str, Any]
    ) -> None:
        response = await admin.post("/overlays", json={"patch": patch})

        assert response.status_code == 422
        assert "seed-only" in response.json()["detail"]
        assert "public_tls" in response.json()["detail"]
        _assert_nothing_changed(public_bundle)

    async def test_an_overlay_cannot_set_public_tls_on_a_private_mode_gateway(
        self, tmp_path: Path
    ) -> None:
        """A private-mode seed cannot be switched to public mode through the API."""
        bundle = make_deps(tmp_path)
        async with _client(bundle, ADMIN_TOKEN) as client:
            response = await client.post("/overlays", json={"patch": {"public_tls": tls_block()}})

        assert response.status_code == 422
        assert "seed-only" in response.json()["detail"]
        _assert_nothing_changed(bundle)

    async def test_an_overlay_cannot_set_ca_x509_in_public_mode(
        self, admin: httpx.AsyncClient, public_bundle: DepsBundle
    ) -> None:
        """Rule 1 is unreachable by an overlay: `ca` is not an overlay key either."""
        response = await admin.post(
            "/overlays", json={"patch": {"ca": {"x509": {"generate": True}}}}
        )

        assert response.status_code == 422
        assert "seed-only" in response.json()["detail"]
        _assert_nothing_changed(public_bundle)

    async def test_the_automation_token_cannot_post_an_overlay_at_all(
        self, automation: httpx.AsyncClient, public_bundle: DepsBundle
    ) -> None:
        response = await automation.post("/overlays", json={"patch": {"public_tls": tls_block()}})

        assert response.status_code == 403
        _assert_nothing_changed(public_bundle)

    async def test_the_automation_token_cannot_smuggle_public_tls_into_an_upstream(
        self, automation: httpx.AsyncClient, public_bundle: DepsBundle
    ) -> None:
        response = await automation.put(
            "/upstreams/ssh/auto-x",
            json={"address": f"x.{ZONE}", "public_tls": tls_block()},
        )

        assert response.status_code == 422
        assert "public_tls" in response.text
        _assert_nothing_changed(public_bundle)

    async def test_the_admin_token_cannot_smuggle_public_tls_into_an_upstream(
        self, admin: httpx.AsyncClient, public_bundle: DepsBundle
    ) -> None:
        response = await admin.put(
            "/upstreams/ssh/x", json={"address": f"x.{ZONE}", "public_tls": tls_block()}
        )

        assert response.status_code == 422
        assert "public_tls" in response.text
        _assert_nothing_changed(public_bundle)


class TestAcmeIsSeedOnly:
    """The ACME block and `source: acme` certificates are unreachable by overlays.

    The gate is the top-level key allowlist (`public_tls` is outside it), so it refuses before
    any validation or merge and for every caller that can post a patch.
    """

    @pytest.mark.parametrize("patch", _ACME_PATCHES)
    def test_the_gate_refuses_the_patch_before_validation(self, patch: dict[str, Any]) -> None:
        with pytest.raises(HTTPException) as caught:
            _reject_forbidden_overlay_keys(patch)

        assert caught.value.status_code == 422
        assert "seed-only" in caught.value.detail
        assert "public_tls" in caught.value.detail

    @pytest.mark.parametrize("patch", _ACME_PATCHES)
    async def test_the_admin_token_gets_422_and_nothing_is_persisted(
        self, admin: httpx.AsyncClient, public_bundle: DepsBundle, patch: dict[str, Any]
    ) -> None:
        response = await admin.post("/overlays", json={"patch": patch, "comment": "acme"})

        assert response.status_code == 422
        detail = response.json()["detail"]
        assert "seed-only" in detail
        assert "public_tls" in detail
        _assert_nothing_changed(public_bundle)

    @pytest.mark.parametrize("patch", _ACME_PATCHES)
    async def test_the_automation_token_gets_403_and_nothing_is_persisted(
        self, automation: httpx.AsyncClient, public_bundle: DepsBundle, patch: dict[str, Any]
    ) -> None:
        response = await automation.post("/overlays", json={"patch": patch, "comment": "acme"})

        assert response.status_code == 403
        _assert_nothing_changed(public_bundle)

    @pytest.mark.parametrize("patch", _ACME_PATCHES)
    async def test_an_acme_patch_next_to_an_allowed_key_is_still_refused(
        self, admin: httpx.AsyncClient, public_bundle: DepsBundle, patch: dict[str, Any]
    ) -> None:
        mixed = {"ssh_upstreams": [ssh("host2", f"host2.{ZONE}:22")], **patch}

        response = await admin.post("/overlays", json={"patch": mixed})

        assert response.status_code == 422
        assert "public_tls" in response.json()["detail"]
        _assert_nothing_changed(public_bundle)

    async def test_the_admin_token_cannot_smuggle_acme_settings_into_an_upstream(
        self, admin: httpx.AsyncClient, public_bundle: DepsBundle
    ) -> None:
        response = await admin.put(
            "/upstreams/ssh/x",
            json={"address": f"x.{ZONE}", "public_tls": {"acme": _ACME_BLOCK}},
        )

        assert response.status_code == 422
        assert "public_tls" in response.text
        _assert_nothing_changed(public_bundle)

    async def test_the_automation_token_cannot_smuggle_acme_settings_into_an_upstream(
        self, automation: httpx.AsyncClient, public_bundle: DepsBundle
    ) -> None:
        response = await automation.put(
            "/upstreams/ssh/auto-x",
            json={"address": f"x.{ZONE}", "public_tls": {"certificates": [_ACME_CERT]}},
        )

        assert response.status_code == 422
        assert "public_tls" in response.text
        _assert_nothing_changed(public_bundle)

    async def test_the_acme_block_cannot_be_added_to_a_private_mode_gateway(
        self, tmp_path: Path
    ) -> None:
        bundle = make_deps(tmp_path)
        async with _client(bundle, ADMIN_TOKEN) as client:
            response = await client.post(
                "/overlays", json={"patch": {"public_tls": {"acme": _ACME_BLOCK}}}
            )

        assert response.status_code == 422
        assert "seed-only" in response.json()["detail"]
        _assert_nothing_changed(bundle)

    def test_a_refusal_does_not_echo_patch_values(self) -> None:
        patch = {"public_tls": {"acme": {**_ACME_BLOCK, "email": "secret-contact@example.com"}}}

        with pytest.raises(HTTPException) as caught:
            _reject_forbidden_overlay_keys(patch)

        assert "secret-contact@example.com" not in caught.value.detail


class TestServedNamesInOverlays:
    """Rule 3 as a 422: the candidate state would carry a name that is not a zone DNS name."""

    async def test_a_covered_resource_inside_a_zone_is_accepted(
        self, admin: httpx.AsyncClient, public_bundle: DepsBundle
    ) -> None:
        """Control: the public-mode seed accepts an in-zone, covered overlay."""
        response = await admin.post(
            "/overlays",
            json={"patch": {"ssh_upstreams": [ssh("host2", f"host2.{ZONE}:22")]}, "comment": "ok"},
        )

        assert response.status_code == 201, response.text
        assert [o.id for o in public_bundle.store.list()] == ["0001-ok"]

    @pytest.mark.parametrize(
        ("patch", "entry", "field", "shown"),
        [
            pytest.param(
                {"ssh_upstreams": [ssh("host2", "10.0.0.6:22")]},
                "host2", "address", "10.0.0.6", id="ip-literal",
            ),
            pytest.param(
                {"ssh_upstreams": [ssh("host2", "host2")]},
                "host2", "address", "host2", id="single-label",
            ),
            pytest.param(
                {"ssh_upstreams": [ssh("host2", f"my_host.{ZONE}")]},
                "host2", "address", f"my_host.{ZONE}", id="underscore",
            ),
            pytest.param(
                {"ssh_upstreams": [ssh("host2", "host2.example.net")]},
                "host2", "address", "host2.example.net", id="outside-every-zone",
            ),
            pytest.param(
                {"k8s_clusters": [k8s("prod", "kubernetes.default.svc")]},
                "prod", "address", "kubernetes.default.svc", id="in-cluster-name",
            ),
            pytest.param(
                {"web_apps": [webapp("app", f"app.{ZONE}", "app.example.net")]},
                "app", "alias", "app.example.net", id="alias-outside-every-zone",
            ),
            pytest.param(
                {"web_apps": [webapp("app", f"app.{ZONE}", "10.0.0.9")]},
                "app", "alias", "10.0.0.9", id="alias-ip-literal",
            ),
        ],
    )
    async def test_an_overlay_with_a_bad_served_name_is_422_naming_entry_and_field(
        self,
        admin: httpx.AsyncClient,
        public_bundle: DepsBundle,
        patch: dict[str, Any],
        entry: str,
        field: str,
        shown: str,
    ) -> None:
        response = await admin.post("/overlays", json={"patch": patch})

        assert response.status_code == 422
        detail = response.json()["detail"]
        assert next(iter(patch)) in detail
        assert entry in detail
        assert field in detail
        assert shown in detail
        _assert_nothing_changed(public_bundle)

    async def test_the_automation_token_is_held_to_the_same_rule(
        self, automation: httpx.AsyncClient, public_bundle: DepsBundle
    ) -> None:
        response = await automation.put(
            "/upstreams/ssh/auto-x", json={"address": "auto-x.example.net"}
        )

        assert response.status_code == 422
        assert "auto-x" in response.text
        assert "address" in response.text
        _assert_nothing_changed(public_bundle)

    async def test_a_put_outside_the_zones_is_422_for_the_admin_token(
        self, admin: httpx.AsyncClient, public_bundle: DepsBundle
    ) -> None:
        response = await admin.put("/upstreams/ssh/host2", json={"address": "10.0.0.6"})

        assert response.status_code == 422
        assert "host2" in response.text
        assert "10.0.0.6" in response.text
        _assert_nothing_changed(public_bundle)


class TestCoverageInOverlays:
    """Rule 5 as a 422: every served name must match exactly one certificate."""

    async def test_an_overlay_name_no_certificate_covers_is_422_naming_it(
        self, admin: httpx.AsyncClient, public_bundle: DepsBundle
    ) -> None:
        """`a.b.<zone>` is inside the zone but two labels deep: `*.<zone>` does not match."""
        served = f"a.b.{ZONE}"
        response = await admin.post(
            "/overlays", json={"patch": {"ssh_upstreams": [ssh("deep", served)]}}
        )

        assert response.status_code == 422
        assert served in response.json()["detail"]
        _assert_nothing_changed(public_bundle)

    async def test_an_overlay_alias_no_certificate_covers_is_422_naming_it(
        self, admin: httpx.AsyncClient, public_bundle: DepsBundle
    ) -> None:
        alias = f"docs.team.{ZONE}"
        response = await admin.post(
            "/overlays",
            json={"patch": {"web_apps": [webapp("app", f"app.{ZONE}", alias)]}},
        )

        assert response.status_code == 422
        assert alias in response.json()["detail"]
        _assert_nothing_changed(public_bundle)

    async def test_an_overlay_name_two_certificates_cover_is_422_naming_both(
        self, admin: httpx.AsyncClient, public_bundle: DepsBundle
    ) -> None:
        """`api.<zone>` matches both `wildcard` and `api-specific`."""
        served = f"api.{ZONE}"
        response = await admin.post(
            "/overlays", json={"patch": {"ssh_upstreams": [ssh("api", served)]}}
        )

        assert response.status_code == 422
        detail = response.json()["detail"]
        assert served in detail
        assert "wildcard" in detail
        assert "api-specific" in detail
        _assert_nothing_changed(public_bundle)

    async def test_an_overlay_alias_two_certificates_cover_is_422(
        self, admin: httpx.AsyncClient, public_bundle: DepsBundle
    ) -> None:
        response = await admin.post(
            "/overlays",
            json={"patch": {"web_apps": [webapp("app", f"app.{ZONE}", f"api.{ZONE}")]}},
        )

        assert response.status_code == 422
        detail = response.json()["detail"]
        assert f"api.{ZONE}" in detail
        assert "wildcard" in detail
        assert "api-specific" in detail
        _assert_nothing_changed(public_bundle)

    async def test_deleting_an_overlay_leaves_the_state_loadable(
        self, admin: httpx.AsyncClient, public_bundle: DepsBundle
    ) -> None:
        """A good overlay can be added and removed; the public-mode state keeps loading."""
        created = await admin.post(
            "/overlays",
            json={"patch": {"ssh_upstreams": [ssh("host2", f"host2.{ZONE}")]}, "comment": "x"},
        )
        assert created.status_code == 201, created.text

        deleted = await admin.delete(f"/overlays/{created.json()['id']}")

        assert deleted.status_code == 204
        assert public_bundle.store.list() == []
