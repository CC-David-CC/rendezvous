# Scoped rendezvous state prerequisite

`leases.py` is a native RAM state component, separate from codiauth. It has no
listener, disk storage, issuer key, credential database, file broker, or account
API. Nothing is started by importing it. The browser does not use it yet.

## Trust boundary

`Admission` is an **internal authenticated result**, not a client JSON object.
A future transport must verify the session's identity and live key proof, bind its
connection to the returned random owner handle, verify the controller's scope
admission, and cap both identity and membership expiry before calling `open`.
Only explicitly public discovery scopes are supported here. Passing an unverified
client-provided Admission directly would bypass the intended authorization.

The transport must serialize access (one event loop), pass the connection's bound
handle rather than a client-selected owner, validate every signed request and SDP
before mutation, sign outgoing lease records, and impose pre-auth connection,
byte, time and reconnect quotas. An `invite` digest and lifetime must come from a
verified, sender-bound signed offer. `answer` must be called only after verifying
the signed answer's author, room, lifetime and `reply_to` hash. This component
receives no SDP or ordinary chat payload and cannot perform those checks itself.
The registry is not safe to expose as a raw RPC API.

## State and limits

- Up to 16 configured public scopes, 64 authenticated owners, one simultaneous
  owner per session, 256 leases total, four leases per owner, one per scope.
- Strict consecutive per-connection request sequence, safe-integer ceiling, and
  at most 32 admitted operations in a rolling 60-second window. Even refused
  authenticated operations consume their sequence and operation quota. Reconnect
  rate limiting is a transport requirement, not provided by this counter.
- Lease lifetime at most 300 seconds (default 120), capped by identity, membership
  and delegated authority expiry. A renewal cannot extend stale admission.
- Lookup requires an existing owned source lease and returns at most four random
  same-scope contacts that explicitly opted into invitations. No pagination,
  global roster, private scope names, or automatic crawling.
- Forwarding permission requires the destination's current opaque reply route,
  matching scope, live source/destination leases, and explicit invitation opt-in.
  Missing, expired and unauthorized destinations use the same unavailable error.
- At most 128 active or answered route records. Exactly the intended destination
  can answer once, bound to the offer digest. The answered digest remains until
  its original expiry, preventing reuse while the leases remain live. Leaving,
  disconnecting or expiry removes dependent routes. Cross-reconnect replay checks
  and live RTC key proof remain transport/application obligations.
- State is lost on restart. There is no persistence, replica protocol, migration,
  authority rotation, Sybil defense, availability guarantee, or Internet proof.

Returned lease data are unsigned dictionaries for the transport to sign; the
registry's owner handles and routing destinations are internal and must never be
included in browser-visible lease records. Session IDs and key references in a
public sample are scoped public discovery data, not a global presence service.

## Evidence

Run `python3 scripts/steward-check.py` from the workspace root. It writes
`.build/checks/steward-state.json` and covers expiry at all three authority bounds,
renewal replay, request ordering, scope/owner isolation, opt-in samples, route
permissions, single answers and retained digest floors, quotas, disconnect,
restart and disposal. These are deterministic state tests, **not WSS, identity,
SDP, real-network or M04 gate completion evidence**.

Next: implement the separately scoped loopback WebSocket transport and signed
challenge/request/response profile, then exercise it with real browser sessions
through the existing peer pool. Public deployment and additional router ports
remain outside this local prerequisite.

## Loopback transport implementation (supersedes the transport TODO above)

`protocol.py` and `server.py` now implement an explicitly started loopback WS
adapter. `StewardServer` requires a root-signed `codi-seed/1`, its trusted release
root key/realm, the delegated service private key, identity policy, endpoint and
an exact Origin allowlist. It rejects an unprovisioned key, bad signature, expired
seed/delegation, invalid scope or capacity grant. `start()` binds only 127.0.0.1.
The provisioned loopback CLI is described below. No public listener, TLS termination or desktop auto-start is installed.

The server uses websockets 17.1 (BSD-3-Clause), with the maintained asyncio API:
https://websockets.readthedocs.io/en/stable/reference/asyncio/server.html .
`dependencies.json` records the downloaded Linux/CPython 3.12 wheel SHA256 and the
unchanged reference JOSE source hash. `requirements.txt` pins the server packages;
the existing project-only `.build/auth-venv` has them installed. No browser package
or runtime download is added.

Service descriptors use bounded, monotonic revisions. The optional durable publisher
reuses exact signed bytes across restart and commits revisions before publication.
Live root-policy reload is supported by the provisioned CLI; see the updates below.

### Signed transport profile

Each WS message is one compact ES256 JWS string, with the corresponding `typ` and
payload `version` equal to the profile name. Binary frames are rejected.

- `codi-steward-challenge/1`: exact fields `version, realm, endpoint, key_id, nonce,
  iat, exp`, signed by the delegated service key. Random nonce expires in 10 sec.
- `codi-steward-auth/1`: exact fields `version, realm, endpoint, nonce, iat, exp,
  identity, scopes`, signed by the identity's bound session key; max lifetime 30
  sec. The server verifies issuer/key binding in server mode and accepts anonymous
  certificate-free keys only under explicit local-development policy. A failed
  server certificate never becomes a local identity. Public scopes must be in the
  service's root delegation; this grants no private-room admission.
- `codi-steward-request/1`: exact fields `version, nonce, sequence, iat, exp,
  operation, body`, signed by the authenticated key; max lifetime 30 sec. Sequence
  starts at one. No client-supplied owner handle can replace the connection binding.
- `codi-steward-response/1`: exact fields `version, nonce, sequence, operation,
  iat, exp, body`, signed by service; max lifetime 30 sec and delegation expiry.
  Authentication response sequence is zero, with operation AUTH. Request responses
  echo the request sequence and operation; clients must check the nonce/binding.
- `codi-steward-event/1`: exact fields `version, nonce, sequence, iat, exp, body`,
  with separate consecutive per-destination event sequence, signed by service and
  capped by route expiry. Contains an unchanged signed offer or answer plus route
  ID, not chat. Clients still verify the inner PeerLink signal and live key proof.
- `codi-steward-lease/1`: signed exact registry view with `version, realm,
  steward_key_id` added. It exposes `lease_id, session_id, key_id, scope,
  routing_revision, renewal_counter, issued_at, expires_at, invitations,
  reply_route`. Owner connection handles are excluded. Lookups return up to four
  of these signed objects, never a roster or pagination cursor.

Request bodies have exact fields:

| Operation | Fields |
|---|---|
| REGISTER_LEASE | scope, invitations |
| RENEW | lease_id, counter |
| JOIN_LOOKUP | lease_id, limit |
| LEAVE | lease_id |
| FORWARD_SIGNAL | kind, signal, source_id, destination_id, reply_route, route_id |

An offer has null route_id and null inner reply_to; source/destination leases and
reply_route authorize that destination. An answer has null source_id,
destination_id, reply_route and uses its assigned route_id; its signed room and
reply_to hash must match the offer. Both inner signals are verified using the
connection key and identity. These preserve the existing `codi-signal+jws`
profile. A transport acknowledgement means forwarding was attempted successfully,
not that a peer accepted a room or established RTC. Refusal or an ambiguous close
requires explicit recovery; the service does not replay unknown outcomes.

### Transport bounds and failures

Before authentication: max 64 raw connections, at most 64 new TCP connections per
rolling minute globally, 5 sec upgrade timeout, 10 sec auth timeout, exact Origin
allowlist, `/rendezvous` path only, auth token max 24576 bytes. All attempts count,
including bad origins. This is a conservative test policy, not Internet abuse
protection or capacity evidence.

All messages max 49152 bytes; two queued incoming frames per socket, compression
disabled, native write high-water mark 16384 bytes. Forwarded inner signal max
min(delegated signal_bytes, 32768) and SDP max 24000 UTF-8 bytes. Incoming work is
serialized per connection and registry commits on one event loop. Outbound sends
share a per-socket lock and a 2 sec timeout including lock wait. Global egress is
limited to 256 messages and 2MiB per rolling minute. Service checks idle authority
expiry at most every 30 sec and cleans leases before operations. WS ping is link
liveness, not a room heartbeat. Connection admission lasts at most 300 sec and no
later than identity/delegation expiry; identity renewal currently requires closing
and authenticating again with the same current session identity.

Protocol errors close with the generic code 1008 / unavailable. No token, SDP,
identity, body, or exception text is logged. Private data files and accounts are
not exposed. No HTTP fallback, chat store, arbitrary URL proxy or host command
endpoint exists. Configuration/reconnect/TLS hardening and metrics need further
work before any public pilot.

### Network evidence

`.build/auth-venv/bin/python scripts/steward-network-check.py` starts and stops its
own disposable loopback HTTP and WS servers and a disposable headless Chrome.
Nineteen checks pass: root/service provisioning, expiry and scope rejection,
signed two-client native offer/answer forwarding and replay refusal, request
binding, origin/size/unsupported-operation rejection, pinned issuer certificate
binding/no local downgrade, and actual Chrome WebCrypto authentication and signed
lease verification **after verifying the root seed and steward descriptor** with
the browser's BootstrapDirectory. Receipt: `.build/checks/steward-network.json`.
SDP is a fixture in forwarding tests. This is WS, not TLS/WSS, browser-to-browser
RTC, LAN, WAN, NAT traversal or complete M04 acceptance evidence.

Next: build the session-owned browser support client and integrate discovery and
signaling with PeerPool; then prove ordinary Chat and separate chess-move room
traffic on real RTCDataChannels through this rendezvous path.

### Signed refusal update

Expected missing/permission/stale-route failures now use the distinct signed
`codi-steward-error/1` profile, correlated to a consumed, rate-admitted request.
The source control connection stays healthy; malformed proofs, sequence violations
and quota exhaustion remain fatal. Recipient send failures also return refusal;
the ambiguous recipient stream closes with 1013 to reset its event nonce/sequence
through bounded recovery. No signaling is automatically replayed. Success schemas
are unchanged. Exact contract and current 26-group/31-state evidence:
[evidence/steward-refusals.md](../evidence/steward-refusals.md).

### Admission maintenance update

RENEW_ADMISSION now renews a still-valid authenticated control admission in place
with the same identity key/account/scope and unchanged membership deadline. It
consumes normal sequence/quota and cannot revive expired authority. Existing leases
require their own renewal. Default duration is 300 seconds; tests use twelve for
real elapsed-deadline proof. The AUTH response reads its actual stored deadline.
The browser automatically maintains it with jitter and rejects invalid response
bounds. Contract and current 28-network-group/37-state evidence:
[evidence/admission-maintenance.md](../evidence/admission-maintenance.md).

### Durable publication option

`PublisherState` and `scripts/serve-steward.py` now support provisioned same-key
restart with a private durable revision/seed ledger and exact cached signed bytes.
Initialization is explicit, corrupt/missing state never resets, and commit precedes
publication. No key/account or lease storage is added to the ledger. A real daemon
SIGKILL/restart, child crash and concurrent-writer tests pass. Entry-point schema,
commands, private/public tree rules and remaining migration/deployment limits:
[evidence/persistent-publisher.md](../evidence/persistent-publisher.md).

### Signed root-policy reload

The provisioned CLI re-reads its private provision file every 30 seconds. Only a
new root-signed seed can change live scopes, limits or delegation expiry. Other
configuration changes require a planned restart. Runtime admissions and leases
are discarded on policy replacement; clients must authenticate again. The public
bundle is written before old control sockets close. Browser reconnect verifies
that bundle using existing pins and revision floors before opening a new socket.
Existing RTC connections remain independent of discovery admission.

Tests, operator procedure and remaining limits:
[evidence/root-policy-reload.md](../evidence/root-policy-reload.md).
