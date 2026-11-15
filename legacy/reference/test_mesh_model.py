"""Pure model/analytical tests only. No browser, v86 or network claim."""
import hashlib
import importlib.util
import json
from pathlib import Path
import random
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'reference'))
sys.path.insert(0,str(ROOT/'shared'))
from mesh_model import (Namespace, PeerBudget, ReplayWindow, VerifiedBlobCache,
                        node_room, sparse_fixture, flood_fixture, MAX_JS_INTEGER)
from capacity import capacity

class NamespaceTests(unittest.TestCase):
    def setUp(self):
        self.tree=Namespace('realm'); self.tree.add('games','realm'); self.tree.add('projects','realm')
        self.tree.add('match7','games')
    def test_node_room_stable_on_move(self):
        before=node_room('match7'); self.tree.move('match7','projects')
        self.assertEqual(before,node_room('match7'))
    def test_node_rooms_distinct(self):
        self.assertNotEqual(node_room('games'),node_room('match7'))
    def test_cycle_rejected_without_mutation(self):
        before=dict(self.tree.parent)
        with self.assertRaises(ValueError):self.tree.move('games','match7')
        self.assertEqual(before,self.tree.parent)
    def test_self_cycle(self):
        with self.assertRaises(ValueError):self.tree.move('games','games')
    def test_root_move(self):
        with self.assertRaises(ValueError):self.tree.move('realm','games')
    def test_unknown_parent(self):
        with self.assertRaises(ValueError):self.tree.add('new','unknown')
    def test_duplicate_node(self):
        with self.assertRaises(ValueError):self.tree.add('games','realm')
    def test_namespace_bound(self):
        tree=Namespace('r',2);tree.add('a','r')
        with self.assertRaises(ValueError):tree.add('b','r')
    def test_no_ancestor_subscription_effect(self):
        budget=PeerBudget();budget.activate('match7',['p1'])
        self.assertEqual(set(budget.groups),{'match7'})
    def test_invalid_id(self):
        for ident in ('', 'a'*257, None):
            with self.subTest(ident=str(ident)[:10]), self.assertRaises(ValueError):node_room(ident)

class PeerBudgetTests(unittest.TestCase):
    def test_endpoint_reuse(self):
        p=PeerBudget(2,4);p.activate('a',['x','y']);p.activate('b',['x'])
        self.assertEqual(len(p.endpoints),2)
    def test_atomic_connection_rejection(self):
        p=PeerBudget(2);p.activate('a',['x']);before=dict(p.groups)
        with self.assertRaises(ValueError):p.activate('b',['y','z'])
        self.assertEqual(p.groups,before)
    def test_hot_group_bound(self):
        p=PeerBudget(4,2);p.activate('a',['x']);p.activate('b',['x'])
        with self.assertRaises(ValueError):p.activate('c',['x'])
        self.assertEqual(len(p.groups),2)
    def test_replacement_counts(self):
        p=PeerBudget(2);p.activate('a',['x']);p.reserve('y')
        with self.assertRaises(ValueError):p.reserve('z')
    def test_pending_deduplicates_existing(self):
        p=PeerBudget(1);p.activate('a',['x']);p.reserve('x')
        self.assertEqual(len(p.endpoints),1)
    def test_leave_shared_peer_stays(self):
        p=PeerBudget();p.activate('a',['x']);p.activate('b',['x']);p.deactivate('a')
        self.assertEqual(p.endpoints,{'x'})
    def test_last_leave_releases(self):
        p=PeerBudget();p.activate('a',['x']);p.deactivate('a');self.assertFalse(p.endpoints)
    def test_reserved_stays_after_leave(self):
        p=PeerBudget();p.reserve('x');p.activate('a',['x']);p.deactivate('a')
        self.assertEqual(p.endpoints,{'x'});p.release('x');self.assertFalse(p.endpoints)
    def test_unknown_leave_idempotent(self):
        p=PeerBudget();p.deactivate('missing');self.assertFalse(p.endpoints)
    def test_no_empty_route(self):
        with self.assertRaises(ValueError):PeerBudget().activate('a',[])
    def test_bounded_endpoint_input(self):
        with self.assertRaises(ValueError):PeerBudget(2).activate('a',['x']*3)
    def test_peer_labels_at_ten_billion_not_global_allocation(self):
        p=PeerBudget();p.activate('g',[f'peer-{10_000_000_000+i}' for i in range(4)])
        self.assertEqual(len(p.endpoints),4)
    def test_large_local_join_sequence_stays_bounded(self):
        p=PeerBudget(12,4)
        for i in range(2000):
            p.activate(str(i%4),[f'p{(i+j)%12}' for j in range(3)])
            self.assertLessEqual(len(p.endpoints),12)
            self.assertLessEqual(len(p.groups),4)

class ReplayTests(unittest.TestCase):
    def test_initial(self):self.assertTrue(ReplayWindow().accept(1))
    def test_duplicate(self):
        w=ReplayWindow();w.accept(1);self.assertFalse(w.accept(1))
    def test_reordered(self):
        w=ReplayWindow();self.assertTrue(w.accept(3));self.assertTrue(w.accept(1));self.assertTrue(w.accept(2))
    def test_old_rejected(self):
        w=ReplayWindow(4);w.accept(5);self.assertFalse(w.accept(1))
    def test_window_boundary(self):
        w=ReplayWindow(4);w.accept(5);self.assertTrue(w.accept(2));self.assertFalse(w.accept(2))
    def test_huge_valid_jump_has_bounded_bitmap(self):
        w=ReplayWindow();w.accept(1);w.accept(MAX_JS_INTEGER)
        self.assertLessEqual(w.bitmap.bit_length(),64);self.assertFalse(w.accept(1))
    def test_invalid_sequences(self):
        for n in (0,-1,True,1.5,MAX_JS_INTEGER+1):
            with self.subTest(n=n),self.assertRaises(ValueError):ReplayWindow().accept(n)
    def test_stream_isolation(self):
        a,b=ReplayWindow(),ReplayWindow();a.accept(1);self.assertTrue(b.accept(1))
    def test_random_order_bounded_replay(self):
        seqs=list(range(1,65));random.Random(5).shuffle(seqs);w=ReplayWindow()
        self.assertTrue(all(w.accept(s) for s in seqs))
        self.assertFalse(any(w.accept(s) for s in seqs))

class CacheTests(unittest.TestCase):
    @staticmethod
    def digest(b):return hashlib.sha256(b).hexdigest()
    def put(self,c,b,**kw):c.put(self.digest(b),b,kw.pop('expires',100),kw.pop('now',0),**kw)
    def test_hash_mismatch(self):
        with self.assertRaises(ValueError):VerifiedBlobCache(10,2).put('bad',b'abc',100,0)
    def test_retrieve(self):
        c=VerifiedBlobCache(10,2);self.put(c,b'abc');self.assertEqual(c.get(self.digest(b'abc'),0),b'abc')
    def test_expired_not_advertised(self):
        c=VerifiedBlobCache(10,2);self.put(c,b'abc',expires=1);self.assertIsNone(c.get(self.digest(b'abc'),1))
    def test_oversized_rejected(self):
        with self.assertRaises(ValueError):self.put(VerifiedBlobCache(2,2),b'abc')
    def test_byte_budget_evicts(self):
        c=VerifiedBlobCache(4,5);self.put(c,b'aaa');self.put(c,b'bbb')
        self.assertLessEqual(c.bytes_used,4);self.assertEqual(len(c.items),1)
    def test_entry_budget_evicts(self):
        c=VerifiedBlobCache(100,1);self.put(c,b'a');self.put(c,b'b');self.assertEqual(len(c.items),1)
    def test_pinned_overflow_atomic(self):
        c=VerifiedBlobCache(4,2);self.put(c,b'aaa',pinned=True);before=dict(c.items)
        with self.assertRaises(ValueError):self.put(c,b'bb')
        self.assertEqual(before,c.items)
    def test_pin_is_not_infinite_ttl(self):
        c=VerifiedBlobCache(4,2);self.put(c,b'aaa',pinned=True,expires=1);c.purge(1);self.assertFalse(c.items)
    def test_deduplicated_storage(self):
        c=VerifiedBlobCache(4,2);self.put(c,b'aaa');self.put(c,b'aaa');self.assertEqual(c.bytes_used,3)
    def test_lru_read_preserves_recent(self):
        c=VerifiedBlobCache(9,2);self.put(c,b'a');self.put(c,b'b');c.get(self.digest(b'a'),0);self.put(c,b'c')
        self.assertIn(self.digest(b'a'),c.items);self.assertNotIn(self.digest(b'b'),c.items)
    def test_expired_insert_rejected(self):
        with self.assertRaises(ValueError):self.put(VerifiedBlobCache(9,2),b'a',expires=0)

class AccountingTests(unittest.TestCase):
    def test_one_percent_population(self):
        r=capacity();self.assertEqual(r['active_devices'],100_000_000)
    def test_membership_cells(self):self.assertEqual(capacity()['ideal_full_cells'],781250)
    def test_replicated_records(self):self.assertEqual(capacity()['aggregate_replicated_routing_bytes'],153_600_000_000)
    def test_renewal_bandwidth(self):self.assertEqual(capacity()['aggregate_renewal_payload_bps'],10_240_000_000)
    def test_relay_bandwidth(self):self.assertEqual(capacity()['aggregate_relay_egress_bps'],640_000_000_000)
    def test_full_online_factor(self):
        a,b=capacity(),capacity(online='1')
        self.assertEqual(b['aggregate_relay_egress_bps'],100*a['aggregate_relay_egress_bps'])
    def test_zero_online(self):
        r=capacity(online='0');self.assertEqual(r['active_devices'],0);self.assertEqual(r['minimum_relay_hosts_by_egress_only'],0)
    def test_bad_fractions(self):
        for x in ('-0.1','1.1'):
            with self.subTest(x=x),self.assertRaises(ValueError):capacity(online=x)
    def test_bad_integer(self):
        with self.assertRaises(ValueError):capacity(population=True)
    def test_fanout_lower_bound(self):
        self.assertEqual(capacity(population=10)['one_1024_byte_population_broadcast_recipient_bytes'],9*1024)

class GraphFixtureTests(unittest.TestCase):
    def test_degree_bound(self):
        g=sparse_fixture(4096);self.assertLessEqual(max(map(len,g)),4)
    def test_connected_under_ideal_conditions(self):
        r=flood_fixture(sparse_fixture(1024),0);self.assertEqual(r['delivered'],1024)
    def test_forward_attempt_bound(self):
        r=flood_fixture(sparse_fixture(1024),0);self.assertLessEqual(r['forward_attempts'],4096)
    def test_source_failure_visible(self):
        r=flood_fixture(sparse_fixture(16),0,[0]);self.assertEqual(r['delivered'],0)
    def test_complete_partition_visible(self):
        g=sparse_fixture(32);r=flood_fixture(g,0,g[0]);self.assertEqual(r['delivered'],1)
        self.assertLess(r['delivered'],r['eligible'])
    def test_graph_invalid_count(self):
        with self.assertRaises(ValueError):sparse_fixture(100001)
    def test_singleton(self):self.assertEqual(flood_fixture(sparse_fixture(1),0)['delivered'],1)

if __name__=='__main__':unittest.main()
