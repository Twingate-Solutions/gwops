"""gwops' own gateway id: the registry's record, else the seed's pinned one."""

from collections.abc import Mapping

from gwops.configmodel.schema import EffectiveState

GATEWAY_KEY = "gateway/self"


def gateway_id_for(managed_ids: Mapping[str, str], state: EffectiveState | None) -> str | None:
    """The registry-recorded gateway id, else ``twingate.gateway_id`` from `state`."""
    recorded = managed_ids.get(GATEWAY_KEY)
    return recorded or (state.twingate.gateway_id if state is not None else None)
