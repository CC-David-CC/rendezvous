"""Optional codi-session-ice/1 request capability over the existing issuer.

Legacy requests keep relay. The existing proof verifier, account generation,
session binding and issuance lock remain authoritative; only successful issuance
updates the public preference in the existing bounded RAM session record.
"""
from contextvars import ContextVar
from origin_service.lifecycle import Service,Failure

VERSION='codi-session-ice/1'
_selection=ContextVar('codi_request_ice_preference',default=None)

def public_preference(value):
 value={**value,'preference':{'version':VERSION,'allowed':['relay','all'] if value['iceTransportPolicy']=='all' else ['relay'],'preferred':value['iceTransportPolicy']}}
 value['iceTransportPolicy']='relay'
 return value

class PreferenceService(Service):
 def allowed(self):
  if self.turn_policy is None:return ()
  return ('relay','all') if self.turn_policy.public_config()['iceTransportPolicy']=='all' else ('relay',)
 def config(self):
  value=super().config()
  if self.turn_policy is not None:value['rtc']=public_preference(value['rtc'])
  return value
 def request_preference(self,data):
  if not isinstance(data,dict):raise Failure(400,'Object request required')
  body=dict(data)
  if 'ice_preference' not in body:return body,None
  preference=body.pop('ice_preference')
  if not isinstance(preference,dict) or set(preference)!={'version','transport'} or preference['version']!=VERSION or not isinstance(preference['transport'],str) or preference['transport'] not in ('relay','all'):raise Failure(400,'Invalid ICE preference profile')
  if preference['transport'] not in self.allowed():raise Failure(403,'ICE preference unavailable under the operator policy')
  return body,preference['transport']
 def enter(self,data,key,path):
  body,preference=self.request_preference(data);token=_selection.set(preference or 'relay')
  try:return super().enter(body,key,path)
  finally:_selection.reset(token)
 def continue_session(self,data,key,proof,path,authorization):
  if path.endswith('/logout') and isinstance(data,dict) and 'ice_preference' in data:raise Failure(400,'Logout requires an empty request')
  body,preference=self.request_preference(data);token=_selection.set(preference)
  try:return super().continue_session(body,key,proof,path,authorization)
  finally:_selection.reset(token)
 def _signed_issue(self,session):
  preference=_selection.get()
  if preference is None:preference=session.get('_ice_preference','relay')
  if self.turn_policy is not None and preference not in self.allowed():raise Failure(403,'Session ICE preference unavailable under the operator policy')
  result=super()._signed_issue(session)
  if self.turn_policy is not None:result['rtc']['iceTransportPolicy']=preference
  session['_ice_preference']=preference
  return result
