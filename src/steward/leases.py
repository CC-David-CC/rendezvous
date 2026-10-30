"""Bounded RAM rendezvous state, with no socket, filesystem or account API.

The transport must authenticate a connection before calling open(), and pass
only its internally bound owner handle thereafter. This is not an authenticator.
All scopes here are explicitly public; private admission is deliberately absent.
"""
from dataclasses import dataclass, field
import secrets
import time
import re

class Unavailable(ValueError):
    """Generic route absence, expiry or permission failure."""

@dataclass(frozen=True)
class Admission:
    session_id: str
    key_id: str
    scopes: frozenset[str]
    identity_expiry: int
    membership_expiry: int
    registered_subject: str | None = None

@dataclass
class Owner:
    admission: Admission
    sequence: int = 0
    operations: list = field(default_factory=list)
    frames: list = field(default_factory=list)

@dataclass
class Lease:
    lease_id: str
    owner: str
    scope: str
    revision: int
    counter: int
    issued_at: int
    expires_at: int
    invitations: bool
    reply_route: str
    account_visible: bool = False

class LeaseRegistry:
    MAX_OWNERS=128
    MAX_LEASES=512
    MAX_OWNER_LEASES=4
    MAX_SAMPLE=4
    MAX_OPERATIONS=96
    MAX_ROUTES=256
    MAX_ACCOUNT_DEVICES=16
    MAX_LEASE_CHANNEL_TAGS=32
    MAX_CHANNEL_TAG_BINDINGS=4096
    def __init__(self,scopes,delegation_expiry,*,clock=time.time,lease_seconds=120):
        if not isinstance(scopes,frozenset) or not 1<=len(scopes)<=16 or any(not isinstance(s,str) or len(s)!=43 for s in scopes):
            raise ValueError('Explicit bounded public scopes required')
        if type(delegation_expiry) is not int or type(lease_seconds) is not int or not 1<=lease_seconds<=300:
            raise ValueError('Invalid delegated lifetime')
        self.scopes=scopes;self.delegation_expiry=delegation_expiry;self.clock=clock;self.lease_seconds=lease_seconds
        self.owners={};self.leases={};self.routes={};self.channel_tags={};self.channel_index={};self.channel_bindings=0;self.channel_feeds={};self.closed=False
    def now(self):return int(self.clock())
    def cleanup(self):
        now=self.now()
        for handle,owner in list(self.owners.items()):
            if min(owner.admission.identity_expiry,owner.admission.membership_expiry,self.delegation_expiry)<=now:self.disconnect(handle)
        for key,lease in list(self.leases.items()):
            if lease.expires_at<=now:del self.leases[key]
        for key in list(self.channel_tags):
            if key not in self.leases:self._remove_channel_tags(key)
        for key,route in list(self.routes.items()):
            if route['expires_at']<=now or route['source'] not in self.leases or route['destination'] not in self.leases:del self.routes[key]
    def open(self,admission):
        self.cleanup()
        if self.closed or not isinstance(admission,Admission) or not isinstance(admission.scopes,frozenset) or not admission.scopes or not admission.scopes<=self.scopes:
            raise Unavailable('unavailable')
        if not isinstance(admission.session_id,str) or not 1<=len(admission.session_id)<=80 or not isinstance(admission.key_id,str) or len(admission.key_id)!=43:
            raise ValueError('Invalid authenticated principal')
        if any(type(n) is not int for n in [admission.identity_expiry,admission.membership_expiry]) or min(admission.identity_expiry,admission.membership_expiry,self.delegation_expiry)<=self.now():
            raise Unavailable('unavailable')
        if admission.registered_subject is not None and not self.account_subject(admission.registered_subject):raise ValueError('Invalid registered account')
        # One live control connection per signed session; transport must also rate-limit reconnects.
        if len(self.owners)>=self.MAX_OWNERS or any(o.admission.session_id==admission.session_id for o in self.owners.values()):raise Unavailable('unavailable')
        handle=secrets.token_urlsafe(32);self.owners[handle]=Owner(admission);return handle
    def _owner(self,handle,sequence):
        self.cleanup();owner=self.owners.get(handle)
        if self.closed or owner is None:raise Unavailable('unavailable')
        if type(sequence) is not int or sequence!=owner.sequence+1 or sequence>2**53-1:raise ValueError('Invalid request sequence')
        now=self.now();owner.operations[:]=[t for t in owner.operations if t>now-60]
        if len(owner.operations)>=self.MAX_OPERATIONS:raise Unavailable('unavailable')
        # Consume authenticated requests even if the requested operation is refused.
        owner.sequence=sequence;owner.operations.append(now);return owner
    def renew_admission(self,handle,sequence,admission):
        owner=self._owner(handle,sequence);old=owner.admission
        if not isinstance(admission,Admission) or not isinstance(admission.scopes,frozenset) or admission.session_id!=old.session_id or admission.key_id!=old.key_id or admission.scopes!=old.scopes or admission.membership_expiry!=old.membership_expiry or admission.registered_subject!=old.registered_subject:
            raise ValueError('Admission renewal changed binding')
        if type(admission.identity_expiry) is not int or not self.now()<admission.identity_expiry<=self.now()+300:raise ValueError('Invalid renewed admission lifetime')
        owner.admission=admission
        return min(admission.identity_expiry,admission.membership_expiry,self.delegation_expiry)
    def _lease(self,owner,lease_id):
        lease=self.leases.get(lease_id)
        if not lease or lease.owner!=owner:raise Unavailable('unavailable')
        return lease
    def _expiry(self,owner):
        a=owner.admission;return min(self.now()+self.lease_seconds,a.identity_expiry,a.membership_expiry,self.delegation_expiry)
    @staticmethod
    def account_subject(value):return isinstance(value,str) and re.fullmatch(r'user:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',value) is not None
    def register(self,handle,sequence,scope,*,invitations=False,account_visible=False):
        owner=self._owner(handle,sequence)
        if scope not in owner.admission.scopes or type(invitations) is not bool or type(account_visible) is not bool:raise Unavailable('unavailable')
        if account_visible:
            if owner.admission.registered_subject is None:raise Unavailable('unavailable')
            devices=sum(1 for lease in self.leases.values() if lease.account_visible and self.owners[lease.owner].admission.registered_subject==owner.admission.registered_subject)
            if devices>=self.MAX_ACCOUNT_DEVICES:raise Unavailable('unavailable')
        existing=[l for l in self.leases.values() if l.owner==handle]
        if any(l.scope==scope for l in existing) or len(existing)>=self.MAX_OWNER_LEASES or len(self.leases)>=self.MAX_LEASES:raise Unavailable('unavailable')
        lease=Lease(secrets.token_urlsafe(32),handle,scope,1,0,self.now(),self._expiry(owner),invitations,secrets.token_urlsafe(32),account_visible);self.leases[lease.lease_id]=lease
        return self._view(lease)
    def _view(self,lease):
        a=self.owners[lease.owner].admission
        return {'lease_id':lease.lease_id,'session_id':a.session_id,'key_id':a.key_id,'scope':lease.scope,'routing_revision':lease.revision,'renewal_counter':lease.counter,'issued_at':lease.issued_at,'expires_at':lease.expires_at,'invitations':lease.invitations,'reply_route':lease.reply_route}
    def renew(self,handle,sequence,lease_id,counter):
        owner=self._owner(handle,sequence);lease=self._lease(handle,lease_id)
        if type(counter) is not int or counter!=lease.counter+1 or counter>2**53-1:raise ValueError('Invalid renewal counter')
        lease.counter=counter;lease.issued_at=self.now();lease.expires_at=self._expiry(owner);return self._view(lease)
    def lookup(self,handle,sequence,source_id,limit=4):
        self._owner(handle,sequence);source=self._lease(handle,source_id)
        if type(limit) is not int or not 1<=limit<=self.MAX_SAMPLE:raise ValueError('Bounded sample required')
        candidates=[l for l in self.leases.values() if l.scope==source.scope and l.owner!=handle and l.invitations]
        # A random bounded sample, never a complete roster API or a pagination cursor.
        return [self._view(l) for l in secrets.SystemRandom().sample(candidates,min(limit,len(candidates)))]
    def lookup_accounts(self,handle,sequence,source_id,subjects,limit=4):
        owner=self._owner(handle,sequence);source=self._lease(handle,source_id)
        if owner.admission.registered_subject is None or not source.account_visible:raise Unavailable('unavailable')
        if not isinstance(subjects,list) or not 1<=len(subjects)<=8 or not all(self.account_subject(s) for s in subjects) or len(set(subjects))!=len(subjects):raise ValueError('Bounded exact account IDs required')
        if type(limit) is not int or not 1<=limit<=self.MAX_SAMPLE:raise ValueError('Bounded account sample required')
        wanted=set(subjects);candidates=[l for l in self.leases.values() if l.scope==source.scope and l.owner!=handle and l.account_visible and l.invitations and self.owners[l.owner].admission.registered_subject in wanted]
        chosen=secrets.SystemRandom().sample(candidates,min(limit,len(candidates)))
        return [{'subject':self.owners[l.owner].admission.registered_subject,'lease':self._view(l)} for l in chosen]
    @staticmethod
    def channel_tag(value):
        return isinstance(value,str) and re.fullmatch(r'[A-Za-z0-9_-]{43}',value) is not None
    def _remove_channel_tags(self,lease_id):
        for tag in self.channel_tags.pop(lease_id,()):
            members=self.channel_index[tag];members.remove(lease_id);self.channel_bindings-=1
            if not members:del self.channel_index[tag]
    def announce_channel(self,handle,sequence,lease_id,tag):
        self._owner(handle,sequence);lease=self._lease(handle,lease_id)
        if not self.channel_tag(tag):raise ValueError('Invalid opaque channel tag')
        if not lease.invitations:raise Unavailable('unavailable')
        current=self.channel_tags.get(lease_id,set())
        if tag in current:return
        if len(current)>=self.MAX_LEASE_CHANNEL_TAGS or self.channel_bindings>=self.MAX_CHANNEL_TAG_BINDINGS:raise Unavailable('unavailable')
        self.channel_tags.setdefault(lease_id,set()).add(tag);self.channel_index.setdefault(tag,set()).add(lease_id);self.channel_bindings+=1
    def lookup_channel(self,handle,sequence,lease_id,tag,limit=4):
        self._owner(handle,sequence);source=self._lease(handle,lease_id)
        if not self.channel_tag(tag):raise ValueError('Invalid opaque channel tag')
        if tag not in self.channel_tags.get(lease_id,set()):raise Unavailable('unavailable')
        if type(limit) is not int or not 1<=limit<=self.MAX_SAMPLE:raise ValueError('Bounded sample required')
        candidates=[self.leases[key] for key in self.channel_index.get(tag,()) if self.leases[key].scope==source.scope and self.leases[key].owner!=handle and self.leases[key].invitations]
        return [self._view(l) for l in secrets.SystemRandom().sample(candidates,min(limit,len(candidates)))]
    def channel_frame(self,handle,sequence,source_id,destination_id,tag):
        """Route an ephemeral frame only between live participants of one channel.

        This authorizes a transport route, not channel membership or the frame's
        contents. Recipients still verify the end-to-end peer and channel proofs.
        """
        self.cleanup();owner=self.owners.get(handle)
        if self.closed or owner is None:raise Unavailable('unavailable')
        if type(sequence) is not int or sequence!=owner.sequence+1 or sequence>2**53-1:raise ValueError('Invalid request sequence')
        now=self.now();owner.frames[:]=[t for t in owner.frames if t>now-60]
        if len(owner.frames)>=1200:raise Unavailable('unavailable')
        owner.sequence=sequence;owner.frames.append(now)
        source=self._lease(handle,source_id);destination=self.leases.get(destination_id)
        if not self.channel_tag(tag):raise ValueError('Invalid opaque channel tag')
        destination_owner=self.owners.get(destination.owner) if destination else None
        if owner.admission.registered_subject is None or not destination_owner or destination_owner.admission.registered_subject is None or destination.owner==handle or source.scope!=destination.scope or not source.invitations or not destination.invitations or tag not in self.channel_tags.get(source_id,set()) or tag not in self.channel_tags.get(destination_id,set()):raise Unavailable('unavailable')
        return {'destination_owner':destination.owner,'source_session':owner.admission.session_id,'expires_at':min(source.expires_at,destination.expires_at)}
    def unannounce_channel(self,handle,sequence,lease_id,tag):
        self._owner(handle,sequence);self._lease(handle,lease_id)
        if not self.channel_tag(tag):raise ValueError('Invalid opaque channel tag')
        tags=self.channel_tags.get(lease_id)
        if tags is not None and tag in tags:
            tags.remove(tag);members=self.channel_index[tag];members.remove(lease_id);self.channel_bindings-=1
            if not members:del self.channel_index[tag]
            if not tags:self.channel_tags.pop(lease_id,None)
    def invite(self,handle,sequence,source_id,destination_id,reply_route,signal_hash,signal_expiry):
        self._owner(handle,sequence);source=self._lease(handle,source_id);destination=self.leases.get(destination_id)
        if not destination or destination.owner==handle or destination.scope!=source.scope or not destination.invitations or destination.reply_route!=reply_route:
            raise Unavailable('unavailable')
        if not isinstance(signal_hash,str) or len(signal_hash)!=43 or type(signal_expiry) is not int or signal_expiry<=self.now() or signal_expiry>self.now()+120:raise ValueError('Invalid verified offer lifetime or digest')
        if len(self.routes)>=self.MAX_ROUTES or any(r['hash']==signal_hash for r in self.routes.values()):raise Unavailable('unavailable')
        route_id=secrets.token_urlsafe(32)
        self.routes[route_id]={'source':source_id,'destination':destination_id,'hash':signal_hash,'expires_at':min(signal_expiry,source.expires_at,destination.expires_at)}
        return {'route_id':route_id,'destination_owner':destination.owner,'expires_at':self.routes[route_id]['expires_at']}
    def answer(self,handle,sequence,route_id,reply_to):
        self._owner(handle,sequence);route=self.routes.get(route_id)
        if not route or route.get('answered'):raise Unavailable('unavailable')
        destination=self.leases[route['destination']]
        if destination.owner!=handle or route['hash']!=reply_to:raise Unavailable('unavailable')
        route['answered']=True # Retain the digest floor until expiry; no replay after answering.
        return {'destination_owner':self.leases[route['source']].owner,'expires_at':route['expires_at']}
    def leave(self,handle,sequence,lease_id):
        self._owner(handle,sequence);self._lease(handle,lease_id);del self.leases[lease_id];self.cleanup()
    def disconnect(self,handle):
        self.owners.pop(handle,None)
        for key,lease in list(self.leases.items()):
            if lease.owner==handle:del self.leases[key]
        for key in list(self.channel_tags):
            if key not in self.leases:self._remove_channel_tags(key)
        for key,route in list(self.routes.items()):
            if route['source'] not in self.leases or route['destination'] not in self.leases:del self.routes[key]
    def snapshot(self):
        self.cleanup();return {'owners':len(self.owners),'leases':len(self.leases),'routes':len(self.routes),'closed':self.closed}
    def close(self):
        self.closed=True;self.owners.clear();self.leases.clear();self.routes.clear();self.channel_tags.clear();self.channel_index.clear();self.channel_bindings=0;self.channel_feeds.clear()
