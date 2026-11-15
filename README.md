# WebOS rendezvous source

Owns the shared peer-discovery/signaling service: bounded lease registry, signed protocol, provisioning and root policy, durable publisher, loopback WebSocket adapter, public channel index and TURN credential primitives. This is a platform component with one owned Python package, `steward`, retained from the existing implementation. It does not own Login, Accounts, account files, UI chat, chess moves or official Chat/Chess content publication.

This service is not enabled in the current desktop and is not a minimum-system dependency. Installing this package starts no listener, timer or operator. Future deployment composition remains parent-owned. No new microservice fleet or generic plugin framework is introduced.

Nine core Python modules and the original lease tests were mechanically extracted with their earlier paths and exact blob/mode proof. The subsequent functional commit imports Accounts' public JOSE primitives and documented stateless mount validator, packages the service and ports the test runner. The original test class/assertions remain unchanged. Historical README/dependency receipts under `legacy/` describe the larger former source area; they are provenance, not current supported-feature claims or deployment instructions. Official Chat/Chess publisher modules remain separately preserved pending ownership.

The component must never accept an unauthenticated client dictionary as an Admission. A transport must verify live identity/key proof, scope, deadlines, request ordering and signed signaling; closing a view must not destroy shared network state. Actual server/root custody, publisher restart, signed wire interoperability, browser lifecycle, authenticated agent operations, TLS/WAN/NAT and release acceptance remain explicit gates. Deterministic lease-state tests and package imports alone do not qualify them.

Install only into an isolated environment with reviewed Accounts source and pinned dependencies. Run `python -m unittest discover -s tests -v`. No legacy provision/publish/operator scripts are installed as entrypoints.

Qualification:37 unchanged lease-state tests pass both before extraction and from the installed wheel. All nine installed core modules import with source hidden. Actual signed transport and operational acceptance remain OPEN. See MIGRATION.md and private phase29 evidence.
