"""Journaled issuer-only TURN policy changes; caller holds the instance lock."""
import hashlib,json,re,secrets,stat,subprocess,time
from pathlib import Path
from origin_service import maintenance
from origin_service.turn import TurnPolicy

VERSION='codi-managed-instance/3'
JOURNAL='codi-turn-transition/1'
def write(op,file,value):op.atomic(file,json.dumps(value,indent=2).encode()+b'\n')
def slot(config_path,name):return Path(config_path).parent/name
def validate(op,config,read_secret=True):
 policy=config.get('turn')
 if policy is None:return
 if not isinstance(policy,dict) or set(policy)!={'secretFile','secretSHA256','urls','iceTransportPolicy'} or not isinstance(policy['secretSHA256'],str) or not re.fullmatch('[a-f0-9]{64}',policy['secretSHA256']):raise ValueError('Invalid managed TURN policy')
 TurnPolicy(b'x'*32,policy['urls'],policy['iceTransportPolicy'])
 secret=op.path(policy['secretFile'])
 for tree in [config['stateRoot'],config['release'],str(Path(config['python']).parent.parent)]:
  if secret.is_relative_to(Path(tree)):raise ValueError('TURN secret must be outside state, release and environment')
 if any(secret.is_relative_to(Path(base)) for base in ['/home','/root','/tmp','/var/tmp','/run']):raise ValueError('TURN source secret requires persistent root custody')
 if read_secret:
  if secret.parent.stat().st_uid!=0 or stat.S_IMODE(secret.parent.stat().st_mode)!=0o700:raise ValueError('TURN source secret directory must be root-owned 0700')
  raw=op.read_owned(secret,0,0o600,128)
  if not re.fullmatch(rb'[A-Za-z0-9_-]{32,128}',raw) or hashlib.sha256(raw).hexdigest()!=policy['secretSHA256']:raise ValueError('TURN source secret contents or pin changed')
def policy(op,secret,urls,transport):
 if secret is None or not urls:raise ValueError('Configure TURN requires both a root-private secret file and URLs')
 raw=op.read_owned(op.path(secret),0,0o600,128)
 return {'secretFile':str(secret),'secretSHA256':hashlib.sha256(raw).hexdigest(),'urls':urls,'iceTransportPolicy':transport}
def public_policy(config):
 value=config.get('turn')
 if value is None:return None
 public=TurnPolicy(b'x'*32,value['urls'],value['iceTransportPolicy']).public_config()
 if config.get('release') and json.loads((Path(config['release'])/'connected-release.json').read_text())['version'] in ('codi-connected-development/14','codi-connected-development/15'):
  from origin_service.ice_preference import public_preference
  public=public_preference(public)
 return public
def ready(op,config):
 rtc=op.issuer_config(config).get('rtc',{})
 expected=public_policy(config)
 if expected is None:
  if rtc.get('credentialMode') is not None:raise ValueError('Issuer still advertises disabled TURN policy')
 elif rtc!=expected:raise ValueError('Issuer TURN policy differs from the managed policy')
def validate_pair(op,current,before,after):
 # This is the sole supported metadata migration: checkpointed v2 -> v3.
 if before.get('version') not in ('codi-managed-instance/2',VERSION,'codi-managed-instance/4','codi-managed-instance/5') or before.get('maintenance')!=1 or after.get('version')!=(before['version'] if before['version'] in ('codi-managed-instance/4','codi-managed-instance/5') else VERSION) or after.get('maintenance')!=1:raise ValueError('TURN changes require checkpointed managed metadata')
 stable=lambda value:{k:v for k,v in value.items() if k not in ('version','turn')}
 if current not in (before,after) or stable(before)!=stable(after) or set(after)!=set(before)|{'turn'}:raise ValueError('TURN transition cannot change code, identity, state, mount or ports')
 if before.get('version')=='codi-managed-instance/2' and 'turn' in before:raise ValueError('Legacy metadata cannot carry TURN policy')
 for value in (before,after):
  if value.get('version') in (VERSION,'codi-managed-instance/4','codi-managed-instance/5'):validate(op,value)
def history(op,config,config_path):
 file=slot(config_path,'turn-history.json')
 if not file.exists():return {'version':'codi-turn-history/1','instance':config['instance'],'entries':[]}
 value=json.loads(op.read_owned(file,0,0o600))
 if set(value)!={'version','instance','entries'} or value['version']!='codi-turn-history/1' or value['instance']!=config['instance'] or not isinstance(value['entries'],list) or len(value['entries'])>16:raise ValueError('Invalid TURN policy history')
 return value
def committed(op,config,config_path,journal):return any(entry['id']==journal['id'] and entry['outcome']=='applied' for entry in history(op,config,config_path)['entries'])
def record(op,config,config_path,journal,outcome):
 value=history(op,config,config_path);entry={key:journal[key] for key in ['id','before','after','activeRoles']};entry.update(outcome=outcome,completed=int(time.time()))
 value['entries']=[old for old in value['entries'] if old['id']!=entry['id']]+[entry];value['entries']=value['entries'][-16:];write(op,slot(config_path,'turn-history.json'),value)
def clear(config_path):slot(config_path,'maintenance.json').unlink();maintenance.sync_directory(Path(config_path).parent)
def apply(op,config,config_path):
 op.atomic(Path(config['unitDir'])/op.unit(config,'issuer'),op.render(config,'issuer'),0o644);write(op,config_path,config);op.systemctl('daemon-reload')
def start(op,config,roles,config_path):
 maintenance.guard_epoch(op,config,config_path)
 if roles:
  if op.systemctl('show',op.unit(config,'issuer'),'-p','ActiveState','--value').strip()=='failed':op.systemctl('reset-failed',op.unit(config,'issuer'))
  op.systemctl('start',op.unit(config,'issuer'));op.ready(config,['issuer'])
  pinned=json.loads(op.read_owned(Path(config['stateRoot'])/'public/origin-discovery.json',0,0o444))['identity']
  if op.issuer_config(config)['identity']!=pinned:raise ValueError('Issuer identity pin changed during TURN configuration')
  ready(op,config)
def revert(op,config_path,journal):
 before=journal['before'];op.installed(before);journal['phase']='rolling-back';write(op,slot(config_path,'maintenance.json'),journal)
 op.stop(before,['issuer']);apply(op,before,config_path);start(op,before,journal['activeRoles'],config_path)
 record(op,before,config_path,journal,'reverted');clear(config_path)
 return {'status':'turn-failed-rolled-back','id':journal['id'],'issuerWasRunning':bool(journal['activeRoles']),'otherRolesRestarted':False}
def configure(op,config,config_path,value):
 from origin_service import deployment
 maintenance.require_clean(op,config_path);maintenance.guard(op,config,config_path)
 after={**config,'version':config['version'] if config['version'] in ('codi-managed-instance/4','codi-managed-instance/5') else VERSION,'turn':value};validate_pair(op,config,config,after);op.installed(after);deployment.syntax(op,after,config_path)
 if after==config:return {'status':'turn-already-current','otherRolesRestarted':False}
 selected=deployment.active(op,config);roles=['issuer'] if 'issuer' in selected else []
 journal={'version':JOURNAL,'id':secrets.token_hex(16),'phase':'prepared','before':config,'after':after,'activeRoles':roles,'created':int(time.time())}
 write(op,slot(config_path,'maintenance.json'),journal)
 try:
  op.stop(config,['issuer']);journal['phase']='switching';write(op,slot(config_path,'maintenance.json'),journal);apply(op,after,config_path)
  journal['phase']='starting';write(op,slot(config_path,'maintenance.json'),journal);start(op,after,roles,config_path)
  record(op,after,config_path,journal,'applied');clear(config_path)
  return {'status':'turn-configured','id':journal['id'],'enabled':value is not None,'issuerWasRunning':bool(roles),'otherRolesRestarted':False}
 except (OSError,ValueError,KeyError,subprocess.SubprocessError) as error:
  if committed(op,after,config_path,journal):raise ValueError('TURN policy committed; finish recover-operation') from error
  try:return revert(op,config_path,journal)
  except (OSError,ValueError,subprocess.SubprocessError) as failure:raise ValueError('TURN rollback incomplete; retain journal and use recover-operation: '+str(failure)) from failure
def recover(op,config,config_path):
 journal=json.loads(op.read_owned(slot(config_path,'maintenance.json'),0,0o600))
 if journal.get('version')!=JOURNAL or journal.get('activeRoles') not in ([],['issuer']):raise ValueError('Invalid TURN transition journal')
 validate_pair(op,config,journal['before'],journal['after'])
 if not committed(op,config,config_path,journal):
  result=revert(op,config_path,journal);result['status']='interrupted-turn-rolled-back';return result
 after=journal['after'];op.installed(after);op.stop(after,['issuer']);apply(op,after,config_path);start(op,after,journal['activeRoles'],config_path);clear(config_path)
 return {'status':'committed-turn-recovered','id':journal['id'],'otherRolesRestarted':False}
