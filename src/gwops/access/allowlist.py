"""Guardrails for overlay / admin-API writes: address and access allowlists.

Both allowlists are seed-only (``twingate.address_allowlist``,
``twingate.access_allowlist``) and apply to **every** overlay/API write, admin token
included. They check only what the patch supplies: seed entries and
``twingate.resource_defaults`` are admin-authored and implicitly allowed. An absent
allowlist leaves that dimension unrestricted; an empty list allows nothing.

:func:`check_automation_startup` is the fail-loud startup rule for the automation token:
it is only safe with both allowlists in place, and must differ from the admin token.
"""

import ipaddress
from typing import Any

from gwops.access.precedence import Ref
from gwops.access.resolve import GROUP, SECURITY_POLICY, AccessResolver
from gwops.configmodel.schema import AccessAllowlist, AddressAllowlist, EffectiveState
from gwops.kinds import KINDS
from gwops.renderer.sans import strip_port
from gwops.settings import GwopsSettings
from gwops.tgapi.client import TGClient


def check_automation_startup(settings: GwopsSettings, state: EffectiveState) -> None:
    """Raise ValueError if ``GWOPS_AUTOMATION_TOKEN`` is configured unsafely."""
    token = settings.gwops_automation_token
    if token is None:
        return
    admin = settings.gwops_admin_token
    if admin is not None and token.get_secret_value() == admin.get_secret_value():
        raise ValueError(
            "GWOPS_AUTOMATION_TOKEN must differ from GWOPS_ADMIN_TOKEN: the automation "
            "token is the limited-scope credential handed to unattended callers"
        )
    missing = [
        key
        for key, value in (
            ("twingate.access_allowlist", state.twingate.access_allowlist),
            ("twingate.address_allowlist", state.twingate.address_allowlist),
        )
        if value is None
    ]
    if missing:
        raise ValueError(
            f"GWOPS_AUTOMATION_TOKEN is set but {' and '.join(missing)} "
            f"{'is' if len(missing) == 1 else 'are'} not configured in the seed. "
            "Unattended callers must be limited to approved groups/policies and "
            "addresses: add the allowlist(s), or unset GWOPS_AUTOMATION_TOKEN."
        )


def address_allowed(host: str, allowlist: AddressAllowlist) -> bool:
    """Whether a portless, lowercase `host` is inside the allowlist."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return any(host == s or host.endswith("." + s) for s in allowlist.dns_suffixes)
    return any(ip in ipaddress.ip_network(c, strict=False) for c in allowlist.cidrs)


def _entries(patch: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        entry
        for kind in KINDS
        for entry in patch.get(kind.state_field) or []
        if isinstance(entry, dict) and not entry.get("_delete")
    ]


def address_violations(patch: dict[str, Any], allowlist: AddressAllowlist | None) -> list[str]:
    """Patch-supplied upstream addresses and aliases outside the allowlist (empty when allowed)."""
    if allowlist is None:
        return []
    violations = []
    for entry in _entries(patch):
        for field in ("address", "alias"):
            value = entry.get(field)
            if isinstance(value, str):
                host = strip_port(value.lower())
                if not address_allowed(host, allowlist):
                    violations.append(f"{entry.get('name')!r}: {field} {host!r} is not allowlisted")
    return violations


def _pinned_id(raw: Any) -> str:
    # Called after gwops.access.resolve.pin_patch_access: every ref is {id, name}.
    return str(raw["id"])


async def access_violations(
    resolver: AccessResolver,
    tg: TGClient | None,
    patch: dict[str, Any],
    allowlist: AccessAllowlist | None,
) -> list[str]:
    """Pinned group / policy refs in `patch` whose ids are not allowlisted.

    The allowlist's own references are resolved through `resolver` (cached); a
    TGAPIError or AccessResolutionError there propagates (the caller maps it to 503:
    gwops cannot currently decide what is allowed).
    """
    if allowlist is None:
        return []
    supplied: list[tuple[str, str, str]] = []  # (entry name, what, id)
    for entry in _entries(patch):
        access = entry.get("access")
        if not isinstance(access, dict):
            continue
        for raw in access.get("groups") or []:
            supplied.append((str(entry.get("name")), GROUP, _pinned_id(raw)))
        if access.get("security_policy") is not None:
            supplied.append(
                (str(entry.get("name")), SECURITY_POLICY, _pinned_id(access["security_policy"]))
            )
    if not supplied:
        return []
    assert tg is not None  # pinning already required the client
    allowed = {
        GROUP: await resolver.ids(tg, GROUP, [Ref.of(r) for r in allowlist.groups]),
        SECURITY_POLICY: await resolver.ids(
            tg, SECURITY_POLICY, [Ref.of(r) for r in allowlist.security_policies]
        ),
    }
    return [
        f"{name!r}: {what} {object_id} is not on the access allowlist"
        for name, what, object_id in supplied
        if object_id not in allowed[what]
    ]
