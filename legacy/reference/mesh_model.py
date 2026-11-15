"""Small executable oracles for the v0.3 design, NOT a production P2P runtime.

No networking, signatures, encryption, browser lifetimes or distributed discovery
are implemented here. Inputs must be authenticated at the production boundary.
"""
from __future__ import annotations
from dataclasses import dataclass
from collections import OrderedDict, deque
from hashlib import sha256
from typing import Iterable
import random

MAX_JS_INTEGER = 2**53 - 1


def positive_integer(value: int, name: str, maximum: int = MAX_JS_INTEGER) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError(f'{name} must be an integer in [1, {maximum}]')
    return value


def identifier(value: str) -> str:
    if not isinstance(value, str) or not value or len(value.encode('utf-8')) > 256:
        raise ValueError('identifier must be 1..256 UTF-8 bytes')
    return value


def node_room(node_id: str) -> str:
    """Identity depends on node, not its mutable display name or parent path."""
    return sha256(b'codi-node-room/1\0' + identifier(node_id).encode()).hexdigest()


class Namespace:
    """Small fully loaded fixture. Production needs bounded signed path proofs."""
    def __init__(self, root: str, capacity: int = 128):
        self.capacity = positive_integer(capacity, 'capacity')
        self.parent: dict[str, str | None] = {identifier(root): None}
        self.root = root

    def add(self, node: str, parent: str) -> None:
        identifier(node)
        if node in self.parent or parent not in self.parent:
            raise ValueError('duplicate node or unknown parent')
        if len(self.parent) >= self.capacity:
            raise ValueError('loaded namespace budget exhausted')
        self.parent[node] = parent

    def move(self, node: str, parent: str) -> None:
        if node == self.root or node not in self.parent or parent not in self.parent:
            raise ValueError('unknown node/parent or root move')
        cursor = parent
        while cursor is not None:
            if cursor == node:
                raise ValueError('cycle')
            cursor = self.parent[cursor]
        self.parent[node] = parent


class PeerBudget:
    """Atomic group admission into ONE physical endpoint budget.

    No calls to RTCPeerConnection. Pending/support endpoints are represented by
    reservations; the reserved set and active group endpoints share the same cap.
    """
    def __init__(self, max_connections: int = 24, max_groups: int = 4):
        self.max_connections = positive_integer(max_connections, 'max_connections')
        self.max_groups = positive_integer(max_groups, 'max_groups')
        self.groups: dict[str, frozenset[str]] = {}
        self.reserved: set[str] = set()

    @property
    def endpoints(self) -> frozenset[str]:
        return frozenset(self.reserved).union(*self.groups.values())

    def reserve(self, peer: str) -> None:
        identifier(peer)
        if len(self.endpoints | {peer}) > self.max_connections:
            raise ValueError('connection budget exhausted')
        self.reserved.add(peer)

    def release(self, peer: str) -> None:
        self.reserved.discard(peer)

    def activate(self, group: str, peers: list[str] | tuple[str, ...]) -> None:
        identifier(group)
        if not isinstance(peers, (list, tuple)) or len(peers) > self.max_connections:
            raise ValueError('bounded explicit endpoint list required')
        selected = frozenset(identifier(p) for p in peers)
        if not selected:
            raise ValueError('live subscription needs a route')
        proposal = dict(self.groups)
        proposal[group] = selected
        if len(proposal) > self.max_groups:
            raise ValueError('hot group budget exhausted')
        combined = frozenset(self.reserved).union(*proposal.values())
        if len(combined) > self.max_connections:
            raise ValueError('connection budget exhausted')
        self.groups = proposal

    def deactivate(self, group: str) -> None:
        self.groups.pop(group, None)


class ReplayWindow:
    """Pure sequence bitmap for ONE already-authenticated stream.

    Own this for the full acceptance window. Evicting/recreating it for a still
    admissible old stream would permit replay; this class does not manage leases.
    """
    def __init__(self, bits: int = 64):
        self.width = positive_integer(bits, 'bits', 1024)
        self.high = 0
        self.bitmap = 0
        self.mask = (1 << bits) - 1

    def accept(self, seq: int) -> bool:
        positive_integer(seq, 'sequence')
        if seq > self.high:
            distance = seq - self.high
            # Avoid shifting by an attacker-controlled giant allocation size.
            self.bitmap = 1 if distance >= self.width else ((self.bitmap << distance) | 1) & self.mask
            self.high = seq
            return True
        distance = self.high - seq
        if distance >= self.width or self.bitmap & (1 << distance):
            return False
        self.bitmap |= 1 << distance
        return True


@dataclass(frozen=True)
class Blob:
    payload: bytes
    expires: int
    pinned: bool


class VerifiedBlobCache:
    """Byte/count-limited LRU with TTL; hash equality is NOT publisher trust."""
    def __init__(self, byte_limit: int, entry_limit: int):
        self.byte_limit = positive_integer(byte_limit, 'byte_limit')
        self.entry_limit = positive_integer(entry_limit, 'entry_limit')
        self.items: OrderedDict[str, Blob] = OrderedDict()

    @property
    def bytes_used(self) -> int:
        return sum(len(item.payload) for item in self.items.values())

    def purge(self, now: int) -> None:
        for key in list(self.items):
            if self.items[key].expires <= now:
                del self.items[key]

    def put(self, digest: str, payload: bytes, expires: int, now: int, *, pinned: bool = False) -> None:
        if type(now) is not int or type(expires) is not int or expires <= now:
            raise ValueError('valid integer time window required')
        if not isinstance(payload, bytes) or not payload or len(payload) > self.byte_limit:
            raise ValueError('blob must fit nonempty byte budget')
        if type(pinned) is not bool:
            raise ValueError('boolean pin required')
        if sha256(payload).hexdigest() != digest:
            raise ValueError('content hash mismatch')
        # Construct the complete next state before mutating; pinned overflow fails.
        proposal = OrderedDict((k, v) for k, v in self.items.items() if v.expires > now and k != digest)
        proposal[digest] = Blob(payload, expires, pinned)
        while len(proposal) > self.entry_limit or sum(len(x.payload) for x in proposal.values()) > self.byte_limit:
            candidate = next((k for k, v in proposal.items() if not v.pinned and k != digest), None)
            if candidate is None:
                raise ValueError('cache full of pinned content')
            del proposal[candidate]
        self.items = proposal

    def get(self, digest: str, now: int) -> bytes | None:
        self.purge(now)
        result = self.items.get(digest)
        if result is None:
            return None
        self.items.move_to_end(digest)
        return result.payload


def sparse_fixture(count: int, seed: int = 7) -> list[set[int]]:
    """Central oracle: union of two cycles, degree <= 4, initially connected.

    This does NOT discover peers or repair distributed churn. A browser must NOT
    build this global adjacency list. Used only for a bounded offline test fixture.
    """
    positive_integer(count, 'count', 100_000)
    graph = [set() for _ in range(count)]
    if count == 1:
        return graph
    orders = [list(range(count)), list(range(count))]
    random.Random(seed).shuffle(orders[1])
    for order in orders:
        for a, b in zip(order, order[1:] + order[:1]):
            if a != b:
                graph[a].add(b)
                graph[b].add(a)
    return graph


def flood_fixture(graph: list[set[int]], source: int, disabled: Iterable[int] = ()) -> dict:
    """One idealized deduplicated public event; no delay/loss/crypto/NAT modeled."""
    if type(source) is not int or not 0 <= source < len(graph):
        raise ValueError('source not in graph')
    down = set(disabled)
    reached: set[int] = set()
    queue = deque([source])
    attempts = 0
    while queue:
        current = queue.popleft()
        if current in down or current in reached:
            continue
        reached.add(current)
        for peer in graph[current]:
            attempts += 1
            if peer not in down and peer not in reached:
                queue.append(peer)
    denominator = len(graph) - len(down.intersection(range(len(graph))))
    return {'eligible': denominator, 'delivered': len(reached), 'forward_attempts': attempts,
            'max_degree': max(map(len, graph), default=0), 'no_repair_modeled': True}
