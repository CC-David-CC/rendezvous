"""Operator-only root seed authoring. Never invoked by an HTTP service.

Signed bytes and revision commit before export. Runtime stewards receive a
public provision and their scoped key; the root private directory stays separate.
"""
import fcntl,os,sqlite3,stat,tempfile,time
from contextlib import closing,contextmanager
from pathlib import Path
from urllib.parse import quote,urlsplit
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from .protocol import exact,jose
from .provision import verified_seed

def safe_path(path):
 path=Path(path)
 if not path.is_absolute() or '..' in path.parts:raise ValueError('Absolute private path without traversal required')
 for component in [path,*path.parents]:
  if component.is_symlink():raise ValueError('Private path must not use symlinks')
  if component!=path and component.exists():
   info=component.stat()
   if info.st_mode&0o022 and not (info.st_mode&stat.S_ISVTX and info.st_uid in (0,os.geteuid())):raise ValueError('Unsafe writable private ancestor')
 return path

def private_directory(path):
 path=safe_path(path);info=path.lstat()
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError('Owned 0700 private directory required')
 return path

def private_read(path,maximum=65536):
 path=safe_path(path);private_directory(path.parent)
 try:
  fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
  with os.fdopen(fd,'rb') as source:
   info=os.fstat(source.fileno())
   if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or not 0<=info.st_size<=maximum:raise ValueError('Owned single-link 0600 regular private file required')
   raw=source.read(maximum+1)
   if len(raw)>maximum:raise ValueError('Private file too large')
   return raw
 except OSError:raise ValueError('Private file unavailable') from None

def atomic_private(path,raw):
 path=safe_path(path);private_directory(path.parent)
 if not isinstance(raw,bytes) or len(raw)>65536:raise ValueError('Bounded private bytes required')
 if path.exists() or path.is_symlink():private_read(path)
 fd,name=tempfile.mkstemp(prefix='.policy-',dir=path.parent)
 try:
  with os.fdopen(fd,'wb') as output:output.write(raw);output.flush();os.fsync(output.fileno())
  os.replace(name,path)
  directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
  try:os.fsync(directory)
  finally:os.close(directory)
 finally:
  if os.path.exists(name):os.unlink(name)

def duration(value):
 if type(value) is not int or not 30<=value<=86400:raise ValueError('Root delegation must be 30..86400 seconds')
 return value

class RootAuthority:
 @contextmanager
 def operator(self):
  fd=os.open(self.directory/'.operator.lock',os.O_RDWR|os.O_CREAT|os.O_CLOEXEC|os.O_NOFOLLOW,0o600)
  try:
   info=os.fstat(fd)
   if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1:raise ValueError('Private operator lock required')
   try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
   except BlockingIOError:raise ValueError('Another operator command is in progress') from None
   yield
  finally:os.close(fd)

 @classmethod
 def initialize(cls,directory,template,grant,seconds,*,clock=time.time):
  directory=safe_path(directory);directory.mkdir(mode=0o700,exist_ok=False);private_directory(directory)
  key=ec.generate_private_key(ec.SECP256R1());template={**template,'root_key':jose.public_jwk(key)}
  exact(template,'root_key realm endpoint identity_policy origins')
  if not isinstance(template['origins'],list) or len(template['origins'])!=1:raise ValueError('One explicit origin required')
  origin=urlsplit(template['origins'][0])
  if origin.scheme!='https' or not origin.hostname or origin.username or origin.password or origin.path or origin.query or origin.fragment:raise ValueError('Explicit HTTPS origin required')
  if not isinstance(template['identity_policy'],dict) or template['identity_policy'].get('mode') not in ('local-development','server'):raise ValueError('Explicit identity policy required')
  if template['identity_policy']['mode']=='server' and template['identity_policy'].get('authorityClass')!='development':raise ValueError('Only development identity is supported')
  exact(grant,'key_id public_key endpoints scopes limits failure_domain')
  if grant['endpoints']!=[template['endpoint']] or len(grant['scopes'])!=1:raise ValueError('One bound endpoint and public scope required')
  now=int(clock());seed={'version':'codi-seed/1','realm':template['realm'],'revision':1,'iat':now,'exp':now+duration(seconds),'stewards':[{**grant,'exp':now+seconds}]}
  token=jose.sign(seed,key,'codi-seed/1');verified_seed(token,template['root_key'],template['realm'],now)
  atomic_private(directory/'root.pem',key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
  db=directory/'authority.sqlite3';fd=os.open(db,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600);os.close(fd)
  with closing(sqlite3.connect(db)) as connection:
   connection.execute('PRAGMA synchronous=FULL');connection.execute('CREATE TABLE authority (id INTEGER PRIMARY KEY CHECK(id=1), binding TEXT NOT NULL, revision INTEGER NOT NULL, token TEXT NOT NULL)')
   connection.execute('INSERT INTO authority VALUES (1,?,?,?)',(jose.dumps({'template':template,'grant':grant}),1,token));connection.execute('PRAGMA user_version=1');connection.commit()
  return cls(directory,clock=clock)

 def __init__(self,directory,*,clock=time.time):
  self.directory=private_directory(directory);self.clock=clock;self.db=self.directory/'authority.sqlite3'
  self.key=serialization.load_pem_private_key(private_read(self.directory/'root.pem'),password=None)
  if not isinstance(self.key,ec.EllipticCurvePrivateKey) or not isinstance(self.key.curve,ec.SECP256R1):raise ValueError('P-256 root key required')
  with closing(self.connection()) as db:self.row(db)

 def connection(self):
  private_read(self.db,1048576)
  journal=Path(str(self.db)+'-journal')
  if journal.exists() or journal.is_symlink():private_read(journal,1048576)
  db=sqlite3.connect('file:'+quote(str(self.db),safe='/')+'?mode=rw',uri=True,timeout=2)
  db.execute('PRAGMA synchronous=FULL')
  if db.execute('PRAGMA user_version').fetchone()!=(1,):db.close();raise ValueError('Root state version unavailable')
  return db

 def row(self,db):
  rows=db.execute('SELECT binding,revision,token FROM authority').fetchall()
  if len(rows)!=1:raise ValueError('Root policy record missing')
  binding,revision,token=rows[0];binding=jose.loads(binding);exact(binding,'template grant');template=binding['template'];exact(template,'root_key realm endpoint identity_policy origins')
  if jose.thumbprint(template['root_key'])!=jose.thumbprint(jose.public_jwk(self.key)):raise ValueError('Root key does not match existing policy')
  inspected=jose.inspect(token,'codi-seed/1',32768)[1]
  if type(inspected.get('iat')) is not int:raise ValueError('Persisted root issue time unavailable')
  seed=verified_seed(token,template['root_key'],template['realm'],inspected['iat'])
  if type(revision) is not int or revision!=seed['revision'] or seed['stewards']!=[{**binding['grant'],'exp':seed['exp']}] or binding['grant']['endpoints']!=[template['endpoint']]:raise ValueError('Root policy revision or binding mismatch')
  return binding,revision,token,seed

 def provision(self):
  with closing(self.connection()) as db:binding,revision,token,seed=self.row(db)
  return {**binding['template'],'seed':token}

 def renew(self,seconds):
  seconds=duration(seconds)
  with closing(self.connection()) as db:
   db.execute('BEGIN IMMEDIATE');binding,revision,token,old=self.row(db);now=int(self.clock())
   if now<old['iat'] or now+seconds<=old['exp'] or revision>=2**53-1:raise ValueError('Renewal must advance expiry, time and revision')
   seed={**old,'revision':revision+1,'iat':now,'exp':now+seconds,'stewards':[{**binding['grant'],'exp':now+seconds}]}
   token=jose.sign(seed,self.key,'codi-seed/1');verified_seed(token,binding['template']['root_key'],binding['template']['realm'],now)
   db.execute('UPDATE authority SET revision=?,token=? WHERE id=1',(revision+1,token));db.commit()
  return self.provision()

 def recover(self,seconds,minimum_revision,service_key):
  """Explicit offline recovery: advance the root epoch and rotate scoped key.

  minimum_revision comes from the separate operator fence/trusted recovery
  receipt. This is never called by online services or ordinary renewal.
  """
  seconds=duration(seconds)
  if type(minimum_revision) is not int or not 1<=minimum_revision<2**53-1:raise ValueError('Explicit bounded recovery revision floor required')
  public=jose.public_jwk(service_key)
  with closing(self.connection()) as db:
   db.execute('BEGIN IMMEDIATE');binding,revision,token,old=self.row(db);now=int(self.clock())
   if now<old['iat']:raise ValueError('Recovery clock rollback')
   grant={**binding['grant'],'key_id':jose.thumbprint(public),'public_key':public}
   if grant['key_id']==binding['grant']['key_id']:raise ValueError('Recovery requires a fresh scoped key')
   next_revision=max(revision,minimum_revision)+1
   if next_revision>2**53-1:raise ValueError('Root revision exhausted')
   seed={**old,'revision':next_revision,'iat':now,'exp':now+seconds,'stewards':[{**grant,'exp':now+seconds}]}
   token=jose.sign(seed,self.key,'codi-seed/1');verified_seed(token,binding['template']['root_key'],binding['template']['realm'],now)
   db.execute('UPDATE authority SET binding=?,revision=?,token=? WHERE id=1',(jose.dumps({**binding,'grant':grant}),next_revision,token));db.commit()
  return self.provision()
