"""Signed public loopback rendezvous protocol; no account issuance or chat API."""
import secrets
import sys
from pathlib import Path
from .leases import Admission,LeaseRegistry,Unavailable
# Reuse the unmodified pinned reference JOSE implementation, not custom crypto.
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'codiserver-server-v0.3.0'))
from codiauth import jose

CHALLENGE='codi-steward-challenge/1'
AUTH='codi-steward-auth/1'
REQUEST='codi-steward-request/1'
RESPONSE='codi-steward-response/1'
ERROR='codi-steward-error/1'
EVENT='codi-steward-event/1'
LEASE='codi-steward-lease/1'

def exact(p,fields):
    if not isinstance(p,dict) or set(p)!=set(fields.split()):raise ValueError('schema')
def identifier(v):
    if len(jose.unb64(v))!=32:raise ValueError('identifier')
def times(p,now,maximum):
    if any(type(p.get(k)) is not int for k in ('iat','exp')) or not p['iat']<=now+30 or not now<p['exp'] or not 0<p['exp']-p['iat']<=maximum:raise ValueError('expired')
    if 'nbf' in p and (type(p['nbf']) is not int or p['nbf']>now+30 or p['nbf']>p['exp']):raise ValueError('not yet valid')

def identity(i,policy,now):
    exact(i,'sid sub name kind key certificate')
    if not isinstance(i['sid'],str) or not 1<=len(i['sid'])<=80 or not isinstance(i['name'],str) or len(i['name'])>64:raise ValueError('identity')
    key=jose.public_jwk(jose.load_public(i['key']))
    if i['certificate'] is None:
        if policy.get('mode')!='local-development' or i['kind']!='anonymous' or i['sub']!=i['sid']:raise ValueError('certificate required')
        return key,now+300
    if policy.get('mode')!='server':raise ValueError('identity mode')
    header,_,_,_=jose.inspect(i['certificate'],'codi-identity+jwt',16384)
    trusted=next((k for k in policy['authorityKeys'] if k['kid']==header.get('kid')),None)
    if trusted is None:raise ValueError('unknown issuer')
    p=jose.verify(i['certificate'],trusted['jwk'],'codi-identity+jwt',16384);times(p,now,900)
    if p.get('v')!=1 or p.get('iss')!=policy['issuer'] or p.get('aud')!=policy['audience'] or any(p.get(k)!=i[k] for k in ('sid','sub','name','kind')) or i['kind'] not in ('anonymous','registered') or jose.thumbprint(p['cnf']['jwk'])!=jose.thumbprint(key):raise ValueError('identity binding')
    return key,p['exp']

class Protocol:
    def __init__(self,registry,realm,endpoint,service_key,policy,admission_seconds=300):
        identifier(realm)
        if type(admission_seconds) is not int or not 10<=admission_seconds<=300:raise ValueError('Admission duration')
        self.admission_seconds=admission_seconds;self.registry=registry;self.realm=realm;self.endpoint=endpoint;self.key=service_key;self.key_id=jose.thumbprint(jose.public_jwk(service_key));self.policy=policy
    def sign(self,body,typ):return jose.sign(body,self.key,typ)
    def connect(self):return Connection(self)
    def lease(self,record):
        return self.sign({'version':LEASE,'realm':self.realm,'steward_key_id':self.key_id,**record},LEASE)

class Connection:
    def __init__(self,protocol):
        self.p=protocol;self.nonce=secrets.token_urlsafe(32);self.deadline=protocol.registry.now()+10;self.handle=None;self.key=None;self.public=None;self.events=0;self.admission_counter=0
    def challenge(self):
        now=self.p.registry.now();return self.p.sign({'version':CHALLENGE,'realm':self.p.realm,'endpoint':self.p.endpoint,'key_id':self.p.key_id,'nonce':self.nonce,'iat':now,'exp':self.deadline},CHALLENGE)
    def authenticate(self,token):
        now=self.p.registry.now()
        if self.handle or now>=self.deadline:raise ValueError('authentication expired')
        _,untrusted,_,_=jose.inspect(token,AUTH,24576)
        key,identity_exp=identity(untrusted['identity'],self.p.policy,now)
        p=jose.verify(token,key,AUTH,24576);exact(p,'version realm endpoint nonce iat exp identity scopes');times(p,now,30)
        if p['version']!=AUTH or p['realm']!=self.p.realm or p['endpoint']!=self.p.endpoint or p['nonce']!=self.nonce:raise ValueError('authentication binding')
        scopes=p['scopes']
        if not isinstance(scopes,list) or not 1<=len(scopes)<=16 or len(set(scopes))!=len(scopes):raise ValueError('scopes')
        for scope in scopes:identifier(scope)
        # Explicit public scopes are joinable; this is not private-room admission.
        subject=p['identity']['sub'] if self.p.policy.get('mode')=='server' and p['identity']['kind']=='registered' and self.p.registry.account_subject(p['identity']['sub']) else None
        self.handle=self.p.registry.open(Admission(p['identity']['sid'],jose.thumbprint(key),frozenset(scopes),min(identity_exp,now+self.p.admission_seconds),self.p.registry.delegation_expiry,subject))
        self.key=key;self.public=p['identity']
        admitted=self.p.registry.owners[self.handle].admission
        return self.response(0,'AUTH',{'expires_at':min(admitted.identity_expiry,admitted.membership_expiry,self.p.registry.delegation_expiry)})
    def response(self,seq,op,body):
        now=self.p.registry.now();return self.p.sign({'version':RESPONSE,'nonce':self.nonce,'sequence':seq,'operation':op,'iat':now,'exp':min(now+30,self.p.registry.delegation_expiry),'body':body},RESPONSE)
    def event(self,body,expiry):
        self.events+=1;now=self.p.registry.now();return self.p.sign({'version':EVENT,'nonce':self.nonce,'sequence':self.events,'iat':now,'exp':min(now+30,expiry),'body':body},EVENT)
    def signal(self,token,kind):
        if not isinstance(token,str) or len(token)>32768:raise ValueError('signal size')
        p=jose.verify(token,self.key,'codi-signal+jws',32768);times(p,self.p.registry.now(),120)
        if not {'v','kind','room','iat','exp','reply_to','sender','sdp'}<=set(p) or not set(p)<= {'v','kind','room','iat','exp','reply_to','sender','sdp','applications','features'}:raise ValueError('signal schema')
        if type(p['v']) is not int or p['v']!=1 or p['kind']!=kind or any(p['sender'].get(k)!=self.public[k] for k in ('sid','sub','name','kind')) or jose.thumbprint(p['sender']['key'])!=jose.thumbprint(self.key) or not isinstance(p['room'],str) or not 1<=len(p['room'])<=80 or not isinstance(p['sdp'],str) or not p['sdp'].startswith('v=0') or len(p['sdp'].encode())>24000:raise ValueError('signal binding')
        if kind=='answer':identifier(p['reply_to'])
        if 'applications' in p and (not isinstance(p['applications'],list) or len(p['applications'])>8 or any(not isinstance(a,str) or len(a)>64 for a in p['applications']) or len(set(p['applications']))!=len(p['applications'])):raise ValueError('applications')
        if 'features' in p and (not isinstance(p['features'],list) or len(p['features'])>4 or any(not isinstance(a,str) or len(a.encode('utf-16-le','surrogatepass'))>128 for a in p['features']) or len(set(p['features']))!=len(p['features'])):raise ValueError('features')
        identity(p['sender'],self.p.policy,self.p.registry.now())
        return p
    def request(self,token):
        if not self.handle:raise ValueError('authentication required')
        p=jose.verify(token,self.key,REQUEST,49152);exact(p,'version nonce sequence iat exp operation body');times(p,self.p.registry.now(),30)
        if p['version']!=REQUEST or p['nonce']!=self.nonce:raise ValueError('request binding')
        try:return self.dispatch(p)
        except Unavailable:
            owner=self.p.registry.owners.get(self.handle)
            # Only a fully authenticated, rate-admitted, sequence-consuming
            # operation may receive a soft refusal. Replay/quota/admission
            # failures remain fatal and cannot mint error responses freely.
            if owner is None or owner.sequence!=p['sequence']:raise
            return self.refusal(p['sequence'],p['operation']),None
    def refusal(self,sequence,operation):
        now=self.p.registry.now()
        return self.p.sign({'version':ERROR,'nonce':self.nonce,'sequence':sequence,'operation':operation,'iat':now,'exp':min(now+30,self.p.registry.delegation_expiry),'body':{'error':'unavailable'}},ERROR)
    def unavailable(self,response):
        _,p,_,_=jose.inspect(response,RESPONSE,49152)
        return self.refusal(p['sequence'],p['operation'])
    def dispatch(self,p):
        body=p['body'];op=p['operation'];seq=p['sequence'];r=self.p.registry;h=self.handle;forward=None
        if op=='RENEW_ADMISSION':
            exact(body,'identity counter')
            if type(body['counter']) is not int or body['counter']!=self.admission_counter+1 or body['counter']>2**53-1:raise ValueError('Admission renewal counter')
            key,identity_exp=identity(body['identity'],self.p.policy,r.now())
            if jose.thumbprint(key)!=jose.thumbprint(self.key) or any(body['identity'][k]!=self.public[k] for k in ('sid','sub','name','kind')):raise ValueError('Admission identity changed')
            owner=r.owners.get(h)
            if owner is None:raise Unavailable('unavailable')
            admission=Admission(owner.admission.session_id,owner.admission.key_id,owner.admission.scopes,min(identity_exp,r.now()+self.p.admission_seconds),owner.admission.membership_expiry,owner.admission.registered_subject)
            expires=r.renew_admission(h,seq,admission);self.public=body['identity'];self.admission_counter=body['counter']
            result={'expires_at':expires,'renewal_counter':self.admission_counter}
        elif op in ('REGISTER_LEASE','REGISTER_ACCOUNT'):
            exact(body,'scope invitations');identifier(body['scope'])
            if type(body['invitations']) is not bool:raise ValueError('invitations flag')
            result={'lease':self.p.lease(r.register(h,seq,body['scope'],invitations=body['invitations'],account_visible=op=='REGISTER_ACCOUNT'))}
        elif op=='RENEW':
            exact(body,'lease_id counter');identifier(body['lease_id']);result={'lease':self.p.lease(r.renew(h,seq,body['lease_id'],body['counter']))}
        elif op=='JOIN_LOOKUP':
            exact(body,'lease_id limit');identifier(body['lease_id']);result={'leases':[self.p.lease(l) for l in r.lookup(h,seq,body['lease_id'],body['limit'])]}
        elif op=='CHANNEL_ANNOUNCE':
            if set(body)=={'lease_id','tag','channel','genesis_hash'}:
                for field in ('channel','genesis_hash'):identifier(body[field])
                if body['tag']!=jose.digest(jose.dumps(['codi-channel-rendezvous/1',body['channel'],body['genesis_hash']])):raise ValueError('channel tag mismatch')
            else:exact(body,'lease_id tag')
            identifier(body['lease_id']);identifier(body['tag']);r.announce_channel(h,seq,body['lease_id'],body['tag']);result={}
        elif op=='CHANNEL_LOOKUP':
            exact(body,'lease_id tag limit');identifier(body['lease_id']);identifier(body['tag']);result={'leases':[self.p.lease(l) for l in r.lookup_channel(h,seq,body['lease_id'],body['tag'],body['limit'])]}
        elif op=='CHANNEL_FRAME':
            exact(body,'source_id destination_id tag channel genesis_hash wire')
            for field in ('source_id','destination_id','tag','channel','genesis_hash'):identifier(body[field])
            if body['tag']!=jose.digest(jose.dumps(['codi-channel-rendezvous/1',body['channel'],body['genesis_hash']])):raise ValueError('channel tag mismatch')
            if not isinstance(body['wire'],str) or not 1<=len(body['wire'])<=32768:raise ValueError('frame size')
            packet=jose.verify(body['wire'],self.key,'codi-peer+jws',32768);times(packet,r.now(),60)
            target=r.channel_frame(h,seq,body['source_id'],body['destination_id'],body['tag'])
            destination=r.leases[body['destination_id']];receiver=r.owners.get(destination.owner)
            if not receiver or packet.get('v')!=1 or packet.get('from')!=self.public['sid'] or packet.get('to')!=receiver.admission.session_id:raise ValueError('frame identity binding')
            result={};forward=(target['destination_owner'],{'kind':'frame','channel_tag':body['tag'],'source_id':body['source_id'],'destination_id':body['destination_id'],'wire':body['wire']},target['expires_at'])
        elif op=='CHANNEL_UNANNOUNCE':
            exact(body,'lease_id tag');identifier(body['lease_id']);identifier(body['tag']);r.unannounce_channel(h,seq,body['lease_id'],body['tag']);result={}
        elif op=='INDEX_SEARCH':
            exact(body,'lease_id query after limit');identifier(body['lease_id'])
            if not isinstance(body['query'],str) or len(body['query'].encode('utf-16-le'))//2>64 or len(body['query'].encode())>256 or not isinstance(body['after'],str) or len(body['after'])>64 or type(body['limit']) is not int or not 1<=body['limit']<=2:raise ValueError('invalid directory search')
            r._owner(h,seq);r._lease(h,body['lease_id']);result={}
        elif op in ('INDEX_PUBLISH','INDEX_PUBLISH_BATCH','INDEX_READ'):
            exact(body,{'INDEX_PUBLISH':'lease_id wire','INDEX_PUBLISH_BATCH':'lease_id wires','INDEX_READ':'lease_id after limit'}[op]);identifier(body['lease_id'])
            r._owner(h,seq);lease=r._lease(h,body['lease_id'])
            # Public metadata only, partitioned by the authenticated public scope.
            # Cursor reads keep response size under the existing signed wire limit.
            
            feed=r.channel_feeds.setdefault(lease.scope,RecentChannelFeed())
            if op=='INDEX_PUBLISH':
                sequence=feed.publish(body['wire'],r.now());result={'sequence':sequence}
            elif op=='INDEX_PUBLISH_BATCH':
                wires=body['wires']
                if not isinstance(wires,list) or not 1<=len(wires)<=4 or any(not isinstance(w,str) for w in wires) or sum(len(w) for w in wires)>24000:raise ValueError('index batch size')
                
                # Validate every signature before changing the feed.
                for wire in wires:
                    listing=verify_listing(wire,r.now());policy=_proof(listing['policyWire'],listing['channel'])
                    if policy.get('stream')!='chat' or policy.get('publicRead') is not True:raise ValueError('Only public chat references may be listed')
                result={'sequences':[feed.publish(wire,r.now()) for wire in wires]}
            else:
                if type(body['limit']) is not int or not 1<=body['limit']<=2:raise ValueError('index page size')
                result=feed.recent(r.now(),after=body['after'],limit=body['limit'])
        elif op=='CHANNEL_SIGNAL':
            exact(body,'kind signal source_id destination_id reply_route route_id tag');identifier(body['tag'])
            if body['kind']=='offer':
                for field in ('source_id','destination_id','reply_route'):identifier(body[field])
                signal=self.signal(body['signal'],'offer')
                if getattr(self.p,'server_channels_only',False) and signal['sdp']!='v=0\r\ns=codi-server-channel/1\r\n':raise ValueError('Server-routed channels required')
                if signal['reply_to'] is not None or body['route_id'] is not None:raise ValueError('offer binding')
                if body['tag'] not in r.channel_tags.get(body['source_id'],set()) or body['tag'] not in r.channel_tags.get(body['destination_id'],set()):
                    r._owner(h,seq);raise Unavailable('unavailable')
                route=r.invite(h,seq,body['source_id'],body['destination_id'],body['reply_route'],jose.digest(body['signal']),signal['exp']);r.routes[route['route_id']].update(room=signal['room'],channel_tag=body['tag'],server_transport=signal['sdp']=='v=0\r\ns=codi-server-channel/1\r\n')
                result={'route_id':route['route_id']};forward=(route['destination_owner'],{'kind':'offer','route_id':route['route_id'],'signal':body['signal'],'channel_tag':body['tag']},route['expires_at'])
                if signal['sdp']=='v=0\r\ns=codi-server-channel/1\r\n':forward[1].update(transport='server',source_id=body['source_id'],destination_id=body['destination_id'])
            elif body['kind']=='answer':
                identifier(body['route_id']);signal=self.signal(body['signal'],'answer');route=r.routes.get(body['route_id'])
                if getattr(self.p,'server_channels_only',False) and signal['sdp']!='v=0\r\ns=codi-server-channel/1\r\n':raise ValueError('Server-routed channels required')
                if any(body[k] is not None for k in ('source_id','destination_id','reply_route')):raise ValueError('answer shape')
                if not route or route.get('room')!=signal['room'] or route.get('channel_tag')!=body['tag'] or route.get('server_transport',False)!=(signal['sdp']=='v=0\r\ns=codi-server-channel/1\r\n') or body['tag'] not in r.channel_tags.get(route['destination'],set()) or body['tag'] not in r.channel_tags.get(route['source'],set()):
                    r._owner(h,seq);raise Unavailable('unavailable')
                source_id,destination_id=route['source'],route['destination']
                target=r.answer(h,seq,body['route_id'],signal['reply_to']);result={};forward=(target['destination_owner'],{'kind':'answer','route_id':body['route_id'],'signal':body['signal'],'channel_tag':body['tag']},min(target['expires_at'],signal['exp']))
                if signal['sdp']=='v=0\r\ns=codi-server-channel/1\r\n':forward[1].update(transport='server',source_id=source_id,destination_id=destination_id)
            else:raise ValueError('signal kind')
        elif op=='ACCOUNT_LOOKUP':
            exact(body,'lease_id subjects limit');identifier(body['lease_id'])
            result={'accounts':[{'subject':item['subject'],'lease':self.p.lease(item['lease'])} for item in r.lookup_accounts(h,seq,body['lease_id'],body['subjects'],body['limit'])]}
        elif op=='LEAVE':
            exact(body,'lease_id');identifier(body['lease_id']);r.leave(h,seq,body['lease_id']);result={}
        elif op=='FORWARD_SIGNAL':
            exact(body,'kind signal source_id destination_id reply_route route_id')
            if body['kind']=='offer':
                for field in ('source_id','destination_id','reply_route'):identifier(body[field])
                signal=self.signal(body['signal'],'offer')
                if signal['reply_to'] is not None or body['route_id'] is not None:raise ValueError('offer binding')
                route=r.invite(h,seq,body['source_id'],body['destination_id'],body['reply_route'],jose.digest(body['signal']),signal['exp']);r.routes[route['route_id']]['room']=signal['room']
                result={'route_id':route['route_id']};forward=(route['destination_owner'],{'kind':'offer','route_id':route['route_id'],'signal':body['signal']},route['expires_at'])
            elif body['kind']=='answer':
                identifier(body['route_id']);signal=self.signal(body['signal'],'answer');route=r.routes.get(body['route_id'])
                if any(body[k] is not None for k in ('source_id','destination_id','reply_route')):raise ValueError('answer shape')
                if not route or route.get('room')!=signal['room'] or 'channel_tag' in route:
                    r._owner(h,seq);raise Unavailable('unavailable')
                target=r.answer(h,seq,body['route_id'],signal['reply_to']);result={};forward=(target['destination_owner'],{'kind':'answer','route_id':body['route_id'],'signal':body['signal']},min(target['expires_at'],signal['exp']))
            else:raise ValueError('signal kind')
        else:raise ValueError('unsupported operation')
        return self.response(seq,op,result),forward
    def close(self):
        if self.handle:self.p.registry.disconnect(self.handle)
        self.handle=None;self.key=None;self.public=None


# Public index verification shares the steward protocol runtime.
from collections import OrderedDict
TYPE='codi-device-channel-key-proof+jws'
KEY_VERSION='codi-device-channel-key/1'
PROFILE='codi-channel-listing/1'
CHANNEL_PROFILE='codi-device-channel/1'


def _exact(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields.split()):
        raise ValueError('invalid schema')


def _proof(wire, channel):
    header, value, _, _ = jose.inspect(wire, TYPE, 16384)
    _exact(header, 'alg typ')
    _exact(value, 'version channel key purpose body')
    key=value['key']
    _exact(key, 'kty crv x y')
    if value['version'] != KEY_VERSION or value['channel'] != channel or value['purpose'] != 'checkpoint':
        raise ValueError('invalid channel proof')
    if jose.digest(jose.dumps([KEY_VERSION, jose.thumbprint(key)])) != channel:
        raise ValueError('wrong channel key')
    return jose.verify(wire, key, TYPE, 16384)['body']


def verify_listing(wire, now):
    if type(now) is not int or now < 0:
        raise ValueError('invalid time')
    header, outer, _, _ = jose.inspect(wire, TYPE, 16384)
    _exact(header, 'alg typ')
    channel=outer.get('channel');identifier(channel)
    body=_proof(wire, channel)
    _exact(body, 'profile category channel genesisHash policyWire label description issued expires')
    if body['profile'] != PROFILE or body['category'] != 'user' or body['channel'] != channel:
        raise ValueError('invalid listing category')
    identifier(body['genesisHash'])
    label, description = body['label'], body['description']
    if not isinstance(label,str) or not label or label.strip()!=label or len(label.encode('utf-16-le'))//2>64 or len(label.encode())>256:
        raise ValueError('invalid label')
    if not isinstance(description,str) or len(description.encode('utf-16-le'))//2>256 or len(description.encode())>1024:
        raise ValueError('invalid description')
    issued, expires = body['issued'], body['expires']
    if type(issued) is not int or type(expires) is not int or issued<0 or issued>now+30 or expires<=now or not 0<expires-issued<=300:
        raise ValueError('expired listing')
    policy_wire=body['policyWire']
    if not isinstance(policy_wire,str) or len(policy_wire)>10000:raise ValueError('invalid policy')
    policy=_proof(policy_wire,channel)
    fields='profile type channel stream validators publicWrite players'
    if isinstance(policy,dict) and 'publicRead' in policy:fields+=' publicRead'
    if isinstance(policy,dict) and 'authorAuthorization' in policy:fields+=' authorAuthorization'
    _exact(policy,fields)
    if policy['profile']!=CHANNEL_PROFILE or policy['type']!='policy' or policy['channel']!=channel or policy['stream'] not in ('chat','chess') or type(policy['publicWrite']) is not bool:
        raise ValueError('invalid policy')
    if 'publicRead' in policy and (type(policy['publicRead']) is not bool or policy['publicWrite'] and not policy['publicRead']):raise ValueError('invalid read policy')
    if 'authorAuthorization' in policy and (policy['stream']!='chat' or 'publicRead' not in policy or policy['authorAuthorization'] not in ('actor-epoch/1','actor-epoch/2')):raise ValueError('invalid author authorization policy')
    validators=policy['validators']
    if not isinstance(validators,list) or not 1<=len(validators)<=31 or any(not isinstance(v,str) for v in validators) or validators!=sorted(set(validators)):
        raise ValueError('invalid validators')
    for value in validators:identifier(value)
    players=policy['players']
    if policy['stream']=='chat':
        if players is not None:raise ValueError('invalid chat players')
    else:
        _exact(players,'white black');identifier(players['white']);identifier(players['black'])
        if players['white']==players['black'] or policy['publicWrite']:raise ValueError('invalid chess players')
    parts=policy_wire.split('.')
    if jose.digest(jose.dumps([CHANNEL_PROFILE,'signed-content',parts[0],parts[1]]))!=body['genesisHash']:
        raise ValueError('wrong policy hash')
    return body


class RecentChannelFeed:
    def __init__(self, *, limit=256, byte_limit=4194304):
        if type(limit) is not int or not 1<=limit<=1024 or type(byte_limit) is not int or not 16384<=byte_limit<=16777216:
            raise ValueError('invalid feed budget')
        self.limit=limit;self.byte_limit=byte_limit;self.entries=OrderedDict();self.bytes=0;self.sequence=0;self.epoch=secrets.token_urlsafe(32)

    def prune(self, now):
        for channel, entry in list(self.entries.items()):
            if entry['expires']<=now:
                self.bytes-=len(entry['wire']);del self.entries[channel]

    def publish(self, wire, now):
        body=verify_listing(wire,now);policy=_proof(body['policyWire'],body['channel']);
        if policy.get('stream')!='chat' or policy.get('publicRead') is not True:raise ValueError('Only public chat references may be listed')
        self.prune(now);channel=body['channel'];old=self.entries.get(channel)
        if old and old['genesisHash']!=body['genesisHash']:raise ValueError('channel policy changed')
        if old and (body['issued']<old['issued'] or old['wire']==wire):return None
        if old:
            self.bytes-=len(old['wire']);del self.entries[channel]
        while self.entries and (len(self.entries)>=self.limit or self.bytes+len(wire)>self.byte_limit):
            _,removed=self.entries.popitem(last=False);self.bytes-=len(removed['wire'])
        self.sequence+=1
        entry={'wire':wire,'sequence':self.sequence,'issued':body['issued'],'expires':body['expires'],'genesisHash':body['genesisHash']}
        self.entries[channel]=entry;self.bytes+=len(wire)
        return self.sequence

    def recent(self, now, *, after=0, limit=32):
        if type(after) is not int or after<0 or type(limit) is not int or not 1<=limit<=64:raise ValueError('invalid cursor')
        self.prune(now)
        # Bounded replay; clients should treat a cursor gap as an incomplete index.
        items=[{'sequence':e['sequence'],'wire':e['wire']} for e in self.entries.values() if e['sequence']>after]
        return {'items':items[:limit],'latest':self.sequence,'oldest':next((e['sequence'] for e in self.entries.values()),self.sequence+1),'epoch':self.epoch}
