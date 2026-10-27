"""Tests for the attribution User-Agent: the builder, the per-request header and `via`."""

from collections.abc import AsyncIterator, Iterator

import httpx
import pytest
import respx

from gwops._version import __version__
from gwops.tgapi.client import PRODUCT, TGClient, attribution_via, build_user_agent

_URL = "https://acme.twingate.com/api/graphql/"
_LIB = f"python-httpx/{httpx.__version__}"
_QUERY = "query ListThings { things { id } }"
_MUTATION = "mutation CreateThing { thingCreate { ok } }"


class TestBuildUserAgent:
    def test_exact_string_for_a_representative_config(self) -> None:
        ua = build_user_agent(
            version="0.3.0", kinds=["ssh", "kubernetes", "ssh"], tls=[], op="read"
        )
        assert ua == (
            f"twingate-gwops-gateway/0.3.0 (kinds=kubernetes,ssh; tls=none; op=read) {_LIB}"
        )

    def test_exact_string_with_every_key(self) -> None:
        ua = build_user_agent(
            version="1.2.3", kinds=["webapp"], tls=["file"], op="write", via="reconcile"
        )
        assert ua == (
            "twingate-gwops-gateway/1.2.3 "
            f"(kinds=webapp; tls=file; op=write; via=reconcile) {_LIB}"
        )

    def test_product_slug_is_the_repo_name(self) -> None:
        assert PRODUCT == "twingate-gwops-gateway"

    def test_sets_are_sorted_and_de_duplicated(self) -> None:
        ua = build_user_agent(
            version="1", kinds=["ssh", "webapp", "kubernetes", "ssh"], tls=["file", "acme", "file"]
        )
        assert "(kinds=kubernetes,ssh,webapp; tls=acme,file)" in ua

    def test_empty_sets_render_none(self) -> None:
        ua = build_user_agent(version="1", kinds=[], tls=[])
        assert "(kinds=none; tls=none)" in ua

    def test_omitted_keys_are_absent_and_the_rest_keep_their_order(self) -> None:
        ua = build_user_agent(version="1", kinds=["ssh"], via="admin_api")
        assert ua == f"twingate-gwops-gateway/1 (kinds=ssh; via=admin_api) {_LIB}"

        ua = build_user_agent(version="1", tls=["acme"], op="read")
        assert ua == f"twingate-gwops-gateway/1 (tls=acme; op=read) {_LIB}"

    def test_no_comment_when_no_keys_apply(self) -> None:
        ua = build_user_agent(version="0.3.0")
        assert ua == f"twingate-gwops-gateway/0.3.0 {_LIB}"
        assert "(" not in ua

    def test_default_version_is_the_package_version(self) -> None:
        assert build_user_agent().startswith(f"{PRODUCT}/{__version__} ")

    def test_lib_token_is_the_runtime_httpx_version(self) -> None:
        ua = build_user_agent(version="1")
        assert ua.endswith(f" python-httpx/{httpx.__version__}")

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"kinds": ["SSH"]},
            {"kinds": ["a b"]},
            {"tls": ["file)"]},
            {"op": "read; via=x"},
            {"via": "admin api"},
        ],
    )
    def test_unsafe_value_raises_value_error(self, kwargs: dict[str, list[str] | str]) -> None:
        with pytest.raises(ValueError, match="outside"):
            build_user_agent(version="1", **kwargs)  # type: ignore[arg-type]


class TestVersionValidation:
    @pytest.mark.parametrize(
        "version",
        ["1.0 (x)", "1.0;x", "a/b", "", "\n1", "1\n", "-1", ".1", "1" * 65, "1.0é"],
        ids=["parens", "semicolon", "slash", "empty", "leading-newline", "trailing-newline",
             "leading-dash", "leading-dot", "65-chars", "non-ascii"],
    )
    def test_unsafe_version_raises_value_error(self, version: str) -> None:
        with pytest.raises(ValueError, match="version"):
            build_user_agent(version=version)

    @pytest.mark.parametrize("version", ["0.3.0", "0.0.0-dev", "0.0.0-dev.abc1234", "1" * 64])
    def test_safe_version_is_accepted_and_rendered_verbatim(self, version: str) -> None:
        assert build_user_agent(version=version).startswith(f"{PRODUCT}/{version} ")

    def test_an_unsafe_version_is_refused_when_building_a_client(self) -> None:
        with pytest.raises(ValueError, match="version"):
            TGClient(network="acme", api_key="k", version="1.0 (x)")


class _Recorder:
    """Records the User-Agent of every request that reaches the fake tenant."""

    def __init__(self) -> None:
        self.user_agents: list[str] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.user_agents.append(request.headers["User-Agent"])
        return httpx.Response(200, json={"data": {"ok": True}})


@pytest.fixture
def recorder(respx_mock: respx.MockRouter) -> _Recorder:
    rec = _Recorder()
    respx_mock.post(_URL).mock(side_effect=rec.handler)
    return rec


@pytest.fixture
async def tg() -> AsyncIterator[TGClient]:
    client = TGClient(network="acme", api_key="tg-secret-key", version="0.3.0")
    yield client
    await client.aclose()


class TestPerRequestHeader:
    async def test_a_query_sends_op_read(self, tg: TGClient, recorder: _Recorder) -> None:
        await tg.execute(_QUERY, {})
        assert recorder.user_agents == [f"twingate-gwops-gateway/0.3.0 (op=read) {_LIB}"]

    async def test_a_mutation_sends_op_write(self, tg: TGClient, recorder: _Recorder) -> None:
        await tg.execute(_MUTATION, {})
        assert recorder.user_agents == [f"twingate-gwops-gateway/0.3.0 (op=write) {_LIB}"]

    async def test_a_comment_before_the_mutation_keyword_still_counts_as_a_write(
        self, tg: TGClient, recorder: _Recorder
    ) -> None:
        await tg.execute("# explains the call\n" + _MUTATION, {})
        assert "op=write" in recorder.user_agents[0]

    async def test_the_client_default_header_is_not_the_library_default(
        self, tg: TGClient
    ) -> None:
        assert tg._client.headers["User-Agent"] == f"twingate-gwops-gateway/0.3.0 {_LIB}"

    async def test_the_default_version_is_the_package_version(
        self, recorder: _Recorder
    ) -> None:
        client = TGClient(network="acme", api_key="k")
        try:
            await client.execute(_QUERY, {})
        finally:
            await client.aclose()
        assert recorder.user_agents[0].startswith(f"{PRODUCT}/{__version__} ")


class TestVia:
    async def test_via_is_absent_outside_attribution_via(
        self, tg: TGClient, recorder: _Recorder
    ) -> None:
        await tg.execute(_QUERY, {})
        assert "via=" not in recorder.user_agents[0]

    @pytest.mark.parametrize("via", ["reconcile", "admin_api"])
    async def test_via_is_sent_inside_attribution_via(
        self, tg: TGClient, recorder: _Recorder, via: str
    ) -> None:
        with attribution_via(via):  # type: ignore[arg-type]
            await tg.execute(_MUTATION, {})
        assert recorder.user_agents == [
            f"twingate-gwops-gateway/0.3.0 (op=write; via={via}) {_LIB}"
        ]

    async def test_via_is_dropped_again_after_the_block(
        self, tg: TGClient, recorder: _Recorder
    ) -> None:
        with attribution_via("admin_api"):
            await tg.execute(_QUERY, {})
        await tg.execute(_QUERY, {})
        assert "via=admin_api" in recorder.user_agents[0]
        assert "via=" not in recorder.user_agents[1]

    async def test_via_is_dropped_when_the_block_raises(
        self, tg: TGClient, recorder: _Recorder
    ) -> None:
        with pytest.raises(RuntimeError), attribution_via("reconcile"):
            raise RuntimeError("boom")
        await tg.execute(_QUERY, {})
        assert "via=" not in recorder.user_agents[0]


class TestSetAttribution:
    async def test_changes_the_next_requests_header(
        self, tg: TGClient, recorder: _Recorder
    ) -> None:
        await tg.execute(_QUERY, {})
        tg.set_attribution(["ssh", "kubernetes"], [])
        await tg.execute(_QUERY, {})
        assert recorder.user_agents == [
            f"twingate-gwops-gateway/0.3.0 (op=read) {_LIB}",
            f"twingate-gwops-gateway/0.3.0 (kinds=kubernetes,ssh; tls=none; op=read) {_LIB}",
        ]

    async def test_updates_the_client_default_without_op_or_via(self, tg: TGClient) -> None:
        tg.set_attribution(["ssh"], ["file", "acme"])
        assert tg._client.headers["User-Agent"] == (
            f"twingate-gwops-gateway/0.3.0 (kinds=ssh; tls=acme,file) {_LIB}"
        )

    async def test_a_later_call_replaces_the_earlier_sets(
        self, tg: TGClient, recorder: _Recorder
    ) -> None:
        tg.set_attribution(["ssh"], ["file"])
        tg.set_attribution(["webapp"], [])
        await tg.execute(_MUTATION, {})
        assert "(kinds=webapp; tls=none; op=write)" in recorder.user_agents[0]

    async def test_combines_with_via_in_the_fixed_order(
        self, tg: TGClient, recorder: _Recorder
    ) -> None:
        tg.set_attribution(["ssh"], ["acme"])
        with attribution_via("reconcile"):
            await tg.execute(_QUERY, {})
        assert recorder.user_agents == [
            f"twingate-gwops-gateway/0.3.0 (kinds=ssh; tls=acme; op=read; via=reconcile) {_LIB}"
        ]


@pytest.fixture(autouse=True)
def _no_real_sleep(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Nothing here retries, but a regression that does must not stall the file."""

    async def _instant(_seconds: float) -> None:
        return None

    monkeypatch.setattr("gwops.tgapi.client.asyncio.sleep", _instant)
    yield
