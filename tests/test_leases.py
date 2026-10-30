#!/usr/bin/env python3
"""Deterministic state tests. Not transport/authentication/network evidence."""
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from steward.leases import Admission,LeaseRegistry,Unavailable

class LeaseChecks(unittest.TestCase):
 def setUp(self):
  self.time=1000;self.scope='a'*43;self.other='b'*43
  self.r=LeaseRegistry(frozenset([self.scope,self.other]),1600,clock=lambda:self.time)
  self.a=self.open('alice');self.b=self.open('bob');self.c=self.open('carol',scopes=[self.other]);self.seq={}
 def open(self,name,scopes=None,identity=1500,membership=1400):
  return self.r.open(Admission(name,'k'*43,frozenset(scopes or [self.scope]),identity,membership))
 def call(self,method,handle,*args,**kwargs):
  self.seq[handle]=self.seq.get(handle,0)+1
  return getattr(self.r,method)(handle,self.seq[handle],*args,**kwargs)
 def register(self,handle,**kw):return self.call('register',handle,self.scope,**kw)
 def pair(self):return self.register(self.a),self.register(self.b,invitations=True)
 def invite(self,a,b):return self.call('invite',self.a,a['lease_id'],b['lease_id'],b['reply_route'],'h'*43,1100)
 def test_expiry_capped_by_membership(self):
  self.time=1350;lease=self.register(self.a);self.assertEqual(1400,lease['expires_at'])
 def test_expiry_capped_by_identity(self):
  d=self.open('d',identity=1050);self.assertEqual(1050,self.register(d)['expires_at'])
 def test_expiry_capped_by_delegation(self):
  self.r.delegation_expiry=1050;self.assertEqual(1050,self.register(self.a)['expires_at'])
 def test_wrong_scope(self):
  with self.assertRaises(Unavailable):self.register(self.c)
 def test_no_duplicate_session_connection(self):
  with self.assertRaises(Unavailable):self.open('alice')
 def test_no_duplicate_scope_lease(self):
  self.register(self.a)
  with self.assertRaises(Unavailable):self.register(self.a)
 def test_request_sequence_replay(self):
  self.register(self.a)
  with self.assertRaises(ValueError):self.r.register(self.a,1,self.other)
 def test_registration_copy(self):
  lease=self.register(self.a);lease['expires_at']=99999;self.assertEqual(1120,next(iter(self.r.leases.values())).expires_at)
 def test_renew_counter(self):
  a=self.register(self.a);self.time=1050
  renewed=self.call('renew',self.a,a['lease_id'],1);self.assertEqual(1170,renewed['expires_at'])
  with self.assertRaises(ValueError):self.call('renew',self.a,a['lease_id'],1)
 def test_expired_lease_cannot_revive(self):
  a=self.register(self.a);self.time=1120
  with self.assertRaises(Unavailable):self.call('renew',self.a,a['lease_id'],1)
 def test_renew_other_owner(self):
  a=self.register(self.a)
  with self.assertRaises(Unavailable):self.call('renew',self.b,a['lease_id'],1)
 def test_lookup_opt_in_only(self):
  a,b=self.pair();self.assertEqual([b],self.call('lookup',self.a,a['lease_id']))
 def test_lookup_requires_own_lease(self):
  a,b=self.pair()
  with self.assertRaises(Unavailable):self.call('lookup',self.b,a['lease_id'])
 def test_lookup_bounded(self):
  a=self.register(self.a)
  for i in range(8):self.register(self.open('peer'+str(i)),invitations=True)
  self.assertEqual(4,len(self.call('lookup',self.a,a['lease_id'])))
  with self.assertRaises(ValueError):self.call('lookup',self.a,a['lease_id'],5)
 def test_lookup_no_cross_scope(self):
  a=self.register(self.a);self.call('register',self.c,self.other,invitations=True)
  self.assertEqual([],self.call('lookup',self.a,a['lease_id']))
 def test_intended_route_and_single_answer(self):
  a,b=self.pair();route=self.invite(a,b);self.assertEqual(self.b,route['destination_owner'])
  reply=self.call('answer',self.b,route['route_id'],'h'*43);self.assertEqual(self.a,reply['destination_owner'])
  with self.assertRaises(Unavailable):self.call('answer',self.b,route['route_id'],'h'*43)
  with self.assertRaises(Unavailable):self.invite(a,b)
 def test_unsolicited_route(self):
  a=self.register(self.a);b=self.register(self.b)
  with self.assertRaises(Unavailable):self.invite(a,b)
 def test_wrong_reply_route(self):
  a,b=self.pair();b['reply_route']='https://arbitrary.example/'
  with self.assertRaises(Unavailable):self.invite(a,b)
 def test_wrong_answer_author(self):
  a,b=self.pair();route=self.invite(a,b)
  with self.assertRaises(Unavailable):self.call('answer',self.c,route['route_id'],'h'*43)
 def test_wrong_answer_hash(self):
  a,b=self.pair();route=self.invite(a,b)
  with self.assertRaises(Unavailable):self.call('answer',self.b,route['route_id'],'x'*43)
 def test_expired_route(self):
  a,b=self.pair();route=self.invite(a,b);self.time=1100
  with self.assertRaises(Unavailable):self.call('answer',self.b,route['route_id'],'h'*43)
 def test_leave_cancels_routes(self):
  a,b=self.pair();self.invite(a,b);self.call('leave',self.a,a['lease_id']);self.assertEqual(0,self.r.snapshot()['routes'])
 def test_disconnect_cancels_routes(self):
  a,b=self.pair();self.invite(a,b);self.r.disconnect(self.b);self.assertEqual(0,self.r.snapshot()['routes'])
 def test_rate_limit(self):
  a=self.register(self.a)
  for _ in range(self.r.MAX_OPERATIONS-1):self.call('lookup',self.a,a['lease_id'])
  with self.assertRaises(Unavailable):self.call('lookup',self.a,a['lease_id'])
 def test_owner_capacity(self):
  for i in range(self.r.MAX_OWNERS-len(self.r.owners)):self.open('extra'+str(i))
  with self.assertRaises(Unavailable):self.open('over-capacity')
 def test_expired_identity_drops_state(self):
  self.register(self.a);self.time=1400;self.assertEqual(0,self.r.snapshot()['owners']);self.assertEqual(0,self.r.snapshot()['leases'])
 def test_global_and_per_owner_lease_capacity(self):
  scopes=frozenset(str(i).zfill(43) for i in range(5));r=LeaseRegistry(scopes,1600,clock=lambda:1000)
  for i in range(64):
   owner=r.open(Admission('owner'+str(i),'k'*43,scopes,1500,1500))
   for seq,scope in enumerate(sorted(scopes)[:4],1):r.register(owner,seq,scope)
   with self.assertRaises(Unavailable):r.register(owner,5,sorted(scopes)[4])
  self.assertEqual(256,r.snapshot()['leases'])
 def test_route_capacity_includes_answered_replay_floors(self):
  a,b=self.pair();self.r.MAX_ROUTES=1;route=self.invite(a,b)
  self.call('answer',self.b,route['route_id'],'h'*43)
  with self.assertRaises(Unavailable):self.call('invite',self.a,a['lease_id'],b['lease_id'],b['reply_route'],'z'*43,1100)
  self.assertEqual(1,self.r.snapshot()['routes'])
 def test_expired_offer_refused_without_allocating_route(self):
  a,b=self.pair()
  with self.assertRaises(ValueError):self.call('invite',self.a,a['lease_id'],b['lease_id'],b['reply_route'],'h'*43,1000)
  self.assertEqual(0,self.r.snapshot()['routes'])
 def test_mutable_scope_admission_refused(self):
  with self.assertRaises(Unavailable):self.r.open(Admission('mutable','k'*43,set([self.scope]),1500,1500))
 def test_admission_renewal_keeps_lease_and_requires_lease_renewal(self):
  d=self.open('renewed',identity=1050);lease=self.register(d);self.time=1040
  old=self.r.owners[d].admission;updated=Admission(old.session_id,old.key_id,old.scopes,1340,old.membership_expiry)
  self.assertEqual(1340,self.call('renew_admission',d,updated))
  self.assertEqual(1050,self.r.leases[lease['lease_id']].expires_at)
  renewed=self.call('renew',d,lease['lease_id'],1);self.assertEqual(1160,renewed['expires_at']);self.assertEqual(lease['lease_id'],renewed['lease_id'])
 def test_admission_renewal_rejects_binding_or_permission_changes(self):
  old=self.r.owners[self.a].admission
  changes=[Admission('other',old.key_id,old.scopes,1300,old.membership_expiry),Admission(old.session_id,'x'*43,old.scopes,1300,old.membership_expiry),Admission(old.session_id,old.key_id,frozenset([self.other]),1300,old.membership_expiry),Admission(old.session_id,old.key_id,old.scopes,1300,1500),Admission(old.session_id,old.key_id,set(old.scopes),1300,old.membership_expiry)]
  for changed in changes:
   with self.assertRaises(ValueError):self.call('renew_admission',self.a,changed)
   self.assertEqual(old,self.r.owners[self.a].admission)
 def test_expired_admission_cannot_be_revived(self):
  d=self.open('expired',identity=1050);old=self.r.owners[d].admission;self.time=1050
  with self.assertRaises(Unavailable):self.call('renew_admission',d,Admission(old.session_id,old.key_id,old.scopes,1350,old.membership_expiry))
 def test_admission_renewal_does_not_reset_quota_or_sequence(self):
  lease=self.register(self.a);old=self.r.owners[self.a].admission
  self.call('renew_admission',self.a,Admission(old.session_id,old.key_id,old.scopes,1300,old.membership_expiry));self.r.MAX_OPERATIONS=2
  with self.assertRaises(Unavailable):self.call('lookup',self.a,lease['lease_id'])
  self.assertEqual(2,self.r.owners[self.a].sequence);self.assertEqual(2,len(self.r.owners[self.a].operations))
 def test_admission_renewal_cannot_extend_membership_or_delegation(self):
  d=self.open('bounded',identity=1010,membership=1015);old=self.r.owners[d].admission;self.time=1005;self.r.delegation_expiry=1012
  self.assertEqual(1012,self.call('renew_admission',d,Admission(old.session_id,old.key_id,old.scopes,1200,old.membership_expiry)))
 def test_admission_renewal_rejects_overlong_identity_window(self):
  old=self.r.owners[self.a].admission
  with self.assertRaises(ValueError):self.call('renew_admission',self.a,Admission(old.session_id,old.key_id,old.scopes,1301,old.membership_expiry))
 def test_close_and_restart_loss(self):
  self.pair();self.r.close();self.r.close();self.assertEqual({'owners':0,'leases':0,'routes':0,'closed':True},self.r.snapshot())
  with self.assertRaises(Unavailable):self.open('later')
  new=LeaseRegistry(frozenset([self.scope]),1600);self.assertEqual(0,new.snapshot()['leases'])

if __name__=='__main__':
 suite=unittest.defaultTestLoader.loadTestsFromTestCase(LeaseChecks);result=unittest.TextTestRunner(verbosity=2).run(suite)
 receipt={'tests':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'passed':result.wasSuccessful(),'scope':'Deterministic RAM lease state only; no WSS, identity or SDP validation evidence'}
 Path('.build/checks/steward-state.json').write_text(json.dumps(receipt,indent=2)+'\n');sys.exit(not result.wasSuccessful())
