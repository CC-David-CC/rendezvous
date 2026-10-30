"""Read only signed steward metadata under an operator-pinned public policy.

The issuer needs no steward private key, publisher ledger or root signing key.
Both file paths are native configuration, never selected by an HTTP request.
"""
import os,stat,threading,time
from pathlib import Path
from urllib.parse import urlsplit
from steward.protocol import exact,identifier,jose,times
from steward.provision import verified_seed

def public_bytes(path,limit):
 path=Path(path)
 if not path.is_absolute() or '..' in path.parts:raise ValueError('Absolute metadata path required')
 for component in [path,*path.parents]:
  if component.is_symlink():raise ValueError('Metadata path must not use symlinks')
 fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as source:
  info=os.fstat(source.fileno())
  if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>limit:raise ValueError('Bounded regular metadata file required')
  raw=source.read(limit+1)
  if len(raw)>limit:raise ValueError('Metadata size limit')
  return raw

class DiscoverySource:
 def __init__(self,policy_file,bundle_file,identity_policy,base_path='',*,clock=time.time):
  self.clock=clock;self.bundle_file=Path(bundle_file);self.lock=threading.RLock();self.cached=None;self.seed_floor=0;self.descriptor_floor=0;self.seed_digest=None
  policy=jose.loads(public_bytes(policy_file,16384));exact(policy,'version pin scope sourcePath identity')
  if policy['version']!='codi-discovery-source/1' or policy['identity']!=identity_policy or policy['sourcePath']!=base_path+'/discovery.json':raise ValueError('Discovery policy must match issuer and application path')
  pin=policy['pin'];exact(pin,'realm rootKey endpoints allowLoopback');identifier(pin['realm']);identifier(policy['scope']);jose.load_public(pin['rootKey'])
  if pin['allowLoopback'] is not False or not isinstance(pin['endpoints'],list) or len(pin['endpoints'])!=1:raise ValueError('One explicitly pinned WSS endpoint required')
  endpoint=urlsplit(pin['endpoints'][0])
  if endpoint.scheme!='wss' or not endpoint.hostname or endpoint.username or endpoint.password or endpoint.query or endpoint.fragment or endpoint.path!=base_path+'/rendezvous':raise ValueError('Pinned endpoint must match application path')
  endpoint.port
  self.policy=policy

 def read(self):
  with self.lock:
   bundle=jose.loads(public_bytes(self.bundle_file,49152));exact(bundle,'version seed descriptor')
   if bundle['version']!='codi-bootstrap-bundle/1':raise ValueError('Unsupported bootstrap bundle')
   now=int(self.clock());pin=self.policy['pin'];seed=verified_seed(bundle['seed'],pin['rootKey'],pin['realm'],now);digest=jose.digest(jose.dumps(seed))
   if seed['revision']<self.seed_floor or seed['revision']==self.seed_floor and self.seed_digest!=digest:raise ValueError('Root policy rollback or fork')
   untrusted=jose.inspect(bundle['descriptor'],'codi-steward/1',8192)[1]
   grant=next((g for g in seed['stewards'] if g['key_id']==untrusted.get('key_id') and untrusted.get('endpoint') in g['endpoints'] and untrusted.get('endpoint') in pin['endpoints'] and self.policy['scope'] in g['scopes']),None)
   if grant is None:raise ValueError('No pinned delegated service')
   descriptor=jose.verify(bundle['descriptor'],grant['public_key'],'codi-steward/1',8192);exact(descriptor,'version realm key_id revision iat exp endpoint scopes limits');times(descriptor,now,300)
   limits=grant['limits'];bounded={'lease_seconds':limits['lease_seconds'],'sample_size':min(4,limits['sample_size']),'signal_bytes':min(32768,limits['signal_bytes'])}
   if descriptor['version']!='codi-steward/1' or descriptor['realm']!=pin['realm'] or descriptor['scopes']!=grant['scopes'] or descriptor['limits']!=bounded or descriptor['exp']>grant['exp'] or type(descriptor['revision']) is not int or descriptor['revision']<max(seed['revision'],self.descriptor_floor):raise ValueError('Descriptor binding or rollback')
   self.seed_floor=seed['revision'];self.seed_digest=digest;self.descriptor_floor=descriptor['revision'];self.cached=bundle
   return dict(bundle)

 def config(self):
  try:bundle=self.read()
  except (OSError,ValueError,KeyError,TypeError):
   with self.lock:bundle=self.cached
  if bundle is None:return None
  return {k:self.policy[k] for k in ['pin','scope','sourcePath']}|{'seed':bundle['seed'],'descriptor':bundle['descriptor']}

class DiscoveryApplication:
 """Serve validated metadata independently of issuer private/public state."""
 def __init__(self,service,source):self.service=service;self.source=source
 def __call__(self,env,start):
  if env.get('PATH_INFO')=='/discovery.json' and env.get('REQUEST_METHOD') in ('GET','HEAD'):
   # Keep the reference host gate; the proxy preserves the external Host.
   if env.get('HTTP_HOST')!=urlsplit(self.service.c.origin).netloc:return self.service.respond(start,403,b'Forbidden','text/plain')
   try:body=jose.dumps(self.source.read()).encode()
   except (OSError,ValueError,KeyError,TypeError):
    start('503 Service Unavailable',[('Content-Type','application/json'),('Content-Length','2'),('Cache-Control','no-store')]);return [b'{}']
   return self.service.respond(start,200,body,'application/json')
  return self.service(env,start)
