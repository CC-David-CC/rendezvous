# Retained legacy backend source

Owner: rendezvous. Discovery, ICE/TURN policy/management and original topology/capacity reference models.

Legacy source only, not a current supported import path or command. Original cross-package namespaces, private imports, target paths, key/account custody, host/network/process actions and fixtures must be ported deliberately before use. Do not add sys.path shims, privileged globals, fake storage or automatic service/firewall actions to make it run. No old module/driver is imported or executed by this extraction; no active backend or minimum dependency changes.

## Source and history

Desktop snapshot `4f72ea86928666189b32f6f05c2c697a37341d06`; exact source baseline `65310f50d4a3d253a88b48581b70cb7f5bc23648`; separate mechanical merge `3919e2a5a06ae87a7ca67a0323730a758e0e5fe3`. Private phase41 retains original/earlier paths, copy-boundary notes and commit/ref maps. No active package/module/test body changed.

| Original path | Retained path |
|---|---|
| `active-system/codiserver-server-v0.3.0/reference/mesh_model.py` | `legacy/reference/mesh_model.py` |
| `active-system/codiserver-server-v0.3.0/shared/capacity.py` | `legacy/reference/capacity.py` |
| `active-system/codiserver-server-v0.3.0/tests/test_mesh_model.py` | `legacy/reference/test_mesh_model.py` |
| `active-system/origin_service/discovery.py` | `legacy/backend/origin_service/discovery.py` |
| `active-system/origin_service/ice_preference.py` | `legacy/backend/origin_service/ice_preference.py` |
| `active-system/origin_service/turn.py` | `legacy/backend/origin_service/turn.py` |
| `active-system/origin_service/turn_management.py` | `legacy/backend/origin_service/turn_management.py` |

These sources remain outside supported package/build/test entrypoints. Existing source baseline failures remain separate; syntax/history checks do not establish old protocol or current application compatibility. Preserve native signed-worker/authorization checks during a real public-interface port. External publication is not authorized by this source retention.
