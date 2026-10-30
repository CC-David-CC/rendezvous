"""Explicit development TURN policy. No public route or shared-secret export."""
import os,re,stat
from pathlib import Path
from urllib.parse import urlsplit
from steward.turn_credentials import mint

class TurnPolicy:
 def __init__(self,secret,urls,transport_policy='relay'):
  if not isinstance(secret,bytes) or not 32<=len(secret)<=128:raise ValueError('Invalid private TURN secret')
  if not isinstance(urls,list) or not 1<=len(urls)<=4 or not all(isinstance(url,str) for url in urls) or len(set(urls))!=len(urls):raise ValueError('Invalid TURN endpoint list')
  for url in urls:
   if not isinstance(url,str) or any(ord(c)<=32 or ord(c)>=127 for c in url) or len(url)>512 or not url.startswith('turns:') or not url.endswith('?transport=tcp'):raise ValueError('TURN/TLS TCP endpoint required')
   authority=url[6:-14]
   parsed=urlsplit('https://'+authority)
   if not parsed.hostname or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment or (parsed.port is not None and not 1<=parsed.port<=65535):raise ValueError('Invalid TURN endpoint')
  if transport_policy not in ('all','relay'):raise ValueError('Invalid ICE transport policy')
  self._secret=secret;self._urls=tuple(urls);self._transport_policy=transport_policy
 def public_config(self):return {'iceServers':[],'credentialMode':'session-turn/1','turnUrls':list(self._urls),'iceTransportPolicy':self._transport_policy}
 def issue(self,deadline,clock):
  credential=mint(self._secret,not_after=deadline,clock=clock)
  return {'iceTransportPolicy':self._transport_policy,'expiresAt':credential.pop('expiresAt'),'iceServers':[{'urls':list(self._urls),**credential}]}

def add_turn_arguments(parser):
 parser.add_argument('--turn-secret-file',type=Path,help='Private native Coturn REST secret file; never a public asset')
 parser.add_argument('--turn-url',action='append',default=[],help='Explicit TURN/TLS TCP URL, repeat up to four times')
 parser.add_argument('--turn-transport-policy',choices=('all','relay'),default='relay',help='Allow direct ICE with TURN fallback, or require relay')

def policy_from_arguments(args,public_root):
 if args.turn_secret_file is None and not args.turn_url:return None
 if args.turn_secret_file is None or not args.turn_url:raise ValueError('TURN secret file and URL must be configured together')
 return load_policy(args.turn_secret_file,args.turn_url,public_root,getattr(args,'turn_transport_policy','relay'))

def systemd_credential(path,directory,info):
 """Accept only the root-owned, read-only systemd credential mount layout.

 systemd uses ACLs to grant a static User access without chowning credentials.
 An environment variable alone never relaxes ordinary secret-file permissions.
 """
 return (str(path.parent)==os.environ.get('CREDENTIALS_DIRECTORY') and
  re.fullmatch(r'/run/credentials/codi-[a-z0-9-]+\.service/turn\.secret',str(path)) is not None and
  directory.st_uid==directory.st_gid==info.st_uid==info.st_gid==0 and
  stat.S_IMODE(directory.st_mode)==0o550 and stat.S_IMODE(info.st_mode)==0o440 and
  bool(os.statvfs(path).f_flag & os.ST_RDONLY) and
  all(parent.stat().st_uid==0 and not parent.stat().st_mode&0o022 for parent in path.parent.parents))

def load_policy(secret_file,urls,public_root,transport_policy='relay'):
 """Load once on startup. Secret rotation requires deliberate process restart."""
 path=Path(secret_file).absolute()
 try:
  for component in [path,*path.parents]:
   if component.is_symlink():raise ValueError('TURN secret path must not use symlinks')
  if path.resolve().is_relative_to(Path(public_root).resolve()):raise ValueError('TURN secret must be outside public files')
  directory=path.parent.stat()
  if not stat.S_ISDIR(directory.st_mode):raise ValueError('TURN secret directory required')
  fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
  with os.fdopen(fd,'rb') as source:
   info=os.fstat(source.fileno())
   private=directory.st_uid==os.getuid() and not directory.st_mode&0o077 and info.st_uid==os.getuid() and not info.st_mode&0o077
   if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or not 32<=info.st_size<=128 or not (private or systemd_credential(path,directory,info)):raise ValueError('TURN secret must be a private owned file or protected systemd credential')
   secret=source.read(129)
  if not re.fullmatch(rb'[A-Za-z0-9_-]{32,128}',secret):raise ValueError('TURN secret file must contain only a 32..128 character token, without newline')
  return TurnPolicy(secret,urls,transport_policy)
 except OSError:raise ValueError('TURN secret file unavailable') from None
