#!/usr/bin/env python3
"""Analytical P2P accounting. Not a benchmark or a ten-billion-peer simulation."""
from __future__ import annotations
import argparse
import json
from fractions import Fraction
from pathlib import Path


def ceil_fraction(value: Fraction) -> int:
    return -(-value.numerator // value.denominator)


def capacity(population=10_000_000_000, online='0.01', memberships=2,
             relay_fraction='0.10', offered_bps=64_000, record_bytes=256,
             port_bps=100_000_000_000, usable='0.70', support_slots=20_000) -> dict:
    policy = json.loads(Path(__file__).with_name('mesh-policy.json').read_text())
    for name, value in {'population':population, 'memberships':memberships,
                       'offered_bps':offered_bps, 'record_bytes':record_bytes,
                       'port_bps':port_bps, 'support_slots':support_slots}.items():
        if type(value) is not int or value < 1:
            raise ValueError(f'{name} must be a positive integer')
    online, relay_fraction, usable = map(Fraction, (online, relay_fraction, usable))
    if not 0 <= online <= 1 or not 0 <= relay_fraction <= 1 or not 0 < usable <= 1:
        raise ValueError('online/relay fractions must be in [0,1]; usable must be in (0,1]')
    active = ceil_fraction(population * online)
    active_memberships = active * memberships
    records = active_memberships * policy['cells']['rendezvous_replicas'] * record_bytes
    renewal = Fraction(records, policy['cells']['lease_refresh_s'])
    relay_bps = active * relay_fraction * offered_bps
    support_connections = active * policy['browser']['support_connections']
    return {
        'classification':'analytical projection; no network execution',
        'excluded':['login/bootstrap load','certificate/index/allocator overhead',
                    'protocol headers/retries','crypto CPU','hot-key skew','regional redundancy'],
        'inputs':{'population':population,'online_fraction':str(online),
                  'memberships':memberships,'relay_fraction':str(relay_fraction),
                  'offered_bps_per_online_device':offered_bps,'routing_record_bytes':record_bytes,
                  'relay_link_bps':port_bps,'usable_link_fraction':str(usable),
                  'support_slots_per_process_UNMEASURED':support_slots},
        'active_devices':active,
        'active_memberships':active_memberships,
        'ideal_full_cells':ceil_fraction(Fraction(active_memberships,policy['cells']['target_members'])),
        'aggregate_replicated_routing_bytes':records,
        'aggregate_renewal_payload_bps':float(renewal * 8),
        'aggregate_relay_egress_bps':float(relay_bps),
        'minimum_relay_hosts_by_egress_only':ceil_fraction(relay_bps / (port_bps * usable)),
        'support_connection_slots':support_connections,
        'minimum_support_processes_by_slots_only':ceil_fraction(Fraction(support_connections,support_slots)),
        'one_1024_byte_population_broadcast_recipient_bytes':max(0,population-1)*1024,
        'warning':'Lower bounds/illustrative inputs, not a deployment size recommendation.'
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--population',type=int,default=10_000_000_000)
    parser.add_argument('--online',default='0.01')
    parser.add_argument('--memberships',type=int,default=2)
    parser.add_argument('--relay-fraction',default='0.10')
    parser.add_argument('--offered-bps',type=int,default=64_000)
    parser.add_argument('--record-bytes',type=int,default=256)
    parser.add_argument('--port-bps',type=int,default=100_000_000_000)
    parser.add_argument('--usable',default='0.70')
    parser.add_argument('--support-slots',type=int,default=20_000)
    args = parser.parse_args()
    try:
        result = capacity(**vars(args))
    except (ValueError, ZeroDivisionError) as exc:
        parser.error(str(exc))
    print(json.dumps(result,indent=2))

if __name__ == '__main__':
    main()
