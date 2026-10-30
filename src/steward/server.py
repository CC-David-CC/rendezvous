"""Loopback-only WebSocket adapter. Never imported or run by codiauth."""
import asyncio
import time
import logging
import sqlite3
import threading
from collections import deque
from urllib.parse import urlsplit
from websockets.asyncio.server import serve,ServerConnection
from websockets.exceptions import ConnectionClosed
from .protocol import Protocol,jose,times,exact,identifier
from .leases import LeaseRegistry,Unavailable
from .provision import verified_seed
from .publisher import PublisherFrozen,PublicChannelDirectory
from origin_service.mount import validate_base_path

class AnonymousIntroductionsDisabled(Exception):
    pass

class EgressWindow:
    """Bounded rolling message and byte accounting for one or all sockets."""
    def __init__(self,count,bytes_limit):
        self.count=count;self.bytes_limit=bytes_limit;self.entries=deque();self.bytes=0
    def prune(self,now):
        while self.entries and self.entries[0][0]<=now-60:
            _,size=self.entries.popleft();self.bytes-=size
    def allows(self,size):return len(self.entries)<self.count and self.bytes+size<=self.bytes_limit
    def add(self,now,size):self.entries.append((now,size));self.bytes+=size

class StewardServer:
    # A restart can cause every existing socket to reconnect at once. Keep a
    # separate bounded burst allowance; the live-socket cap remains explicit.
    MAX_CONNECTIONS=128
    MAX_STARTS_PER_MINUTE=512
    def __init__(self,*,seed,root_key,realm,endpoint,service_key,identity_policy,origins,clock=time.time,admission_seconds=300,publisher_state=None,official_channel_allowed=None,offered_channels_only=False):
        # Deployment metadata is a root-signed public seed, not a service's self-assertion.
        now=int(clock());p=verified_seed(seed,root_key,realm,now)
        key_id=jose.thumbprint(jose.public_jwk(service_key));grants=[g for g in p['stewards'] if g['key_id']==key_id and endpoint in g['endpoints']]
        if len(grants)!=1:raise ValueError('service not delegated')
        grant=grants[0];limits=grant['limits']
        u=urlsplit(endpoint)
        if u.username or u.password or u.query or u.fragment or not u.path.endswith('/rendezvous') or (u.scheme!='wss' and not (u.scheme=='ws' and u.hostname=='127.0.0.1')):raise ValueError('endpoint')
        validate_base_path(u.path[:-len('/rendezvous')]);self.request_path=u.path
        if not origins or len(origins)>8:raise ValueError('explicit origins required')
        self.registry=LeaseRegistry(frozenset(grant['scopes']),grant['exp'],clock=clock,lease_seconds=limits['lease_seconds']);self.registry.MAX_SAMPLE=min(4,limits['sample_size'])
        self.protocol=Protocol(self.registry,realm,endpoint,service_key,identity_policy,admission_seconds);self.origins=list(origins);self.clients={};self.send_locks={};self.active=0;self.wire_count=0;self.starts=[];self.egress=EgressWindow(8192,32*1024*1024);self.socket_egress={};self.frame_egress=EgressWindow(131072,512*1024*1024);self.socket_frame_egress={};self.server=None;self.clock=clock
        if official_channel_allowed is not None and not callable(official_channel_allowed):raise ValueError('Invalid official channel checker')
        if type(offered_channels_only) is not bool:raise ValueError('Invalid channel access policy')
        self.official_channel_allowed=official_channel_allowed;self.offered_channels_only=offered_channels_only
        self.protocol.server_channels_only=offered_channels_only
        self.signal_bytes=min(32768,limits['signal_bytes']);self.seed=seed;self.grant=grant;self.descriptor_lock=threading.RLock();self.descriptor_token=None;self.descriptor_revision=p['revision'];self.seed_payload=p;self.publisher_state=publisher_state;self.root_key=root_key;self.endpoint=endpoint;self.authorized=True;self.policy_frozen=False;self.policy_generation=0;self.anonymous_allowed=True
        if publisher_state is not None:
            publisher_state.bind({'realm':realm,'root_key_id':jose.thumbprint(root_key),'service_key_id':key_id,'endpoint':endpoint},p)
        if publisher_state is None and now>=min(p['iat']+300,grant['exp']):raise ValueError('fresh seed required for service descriptor')
        try:self.public_directory=PublicChannelDirectory(publisher_state.directory if publisher_state is not None else None)
        except (OSError,ValueError,sqlite3.Error):
            logging.error('Public channel directory unavailable; peer introductions remain enabled')
            self.public_directory=None
        self.directory_slots=asyncio.Semaphore(4)
    def ensure_authority(self):
        if not self.authorized or self.policy_frozen or self.registry.now()>=self.registry.delegation_expiry:raise ValueError('Service authority unavailable')
        if self.publisher_state is not None:
            try:self.publisher_state.assert_seed(self.seed_payload)
            except Exception:
                self.authorized=False;self.registry.close();raise
    async def reload_seed(self,token,publish=None):
        p=verified_seed(token,self.root_key,self.protocol.realm,self.registry.now());digest=jose.digest(jose.dumps(p))
        if self.policy_frozen:raise ValueError('Service authority is frozen')
        if p['revision']<self.seed_payload['revision']:raise ValueError('Runtime seed rollback')
        fork=p['revision']==self.seed_payload['revision'] and digest!=jose.digest(jose.dumps(self.seed_payload))
        try:
            if self.publisher_state is not None:self.publisher_state.bind({'realm':self.protocol.realm,'root_key_id':jose.thumbprint(self.root_key),'service_key_id':self.protocol.key_id,'endpoint':self.endpoint},p)
            if fork:raise PublisherFrozen('Authenticated runtime seed fork')
        except PublisherFrozen:
            self.policy_frozen=True;self.authorized=False;self.registry.close();self.policy_generation+=1
            await asyncio.gather(*(ws.close(1008,'unavailable') for ws,_ in list(self.clients.values())),return_exceptions=True)
            raise
        if p['revision']==self.seed_payload['revision']:return False
        # No await until policy, RAM admission and metadata epoch are replaced.
        failure=None
        with self.descriptor_lock:
            previous=self.descriptor_token;old_revision=self.descriptor_revision;self.registry.close();self.policy_generation+=1
            self.seed=token;self.seed_payload=p
            grant=next((g for g in p['stewards'] if g['key_id']==self.protocol.key_id and self.endpoint in g['endpoints']),None)
            self.grant=grant;self.authorized=grant is not None
            if grant is not None:
                limits=grant['limits'];self.registry=LeaseRegistry(frozenset(grant['scopes']),grant['exp'],clock=self.clock,lease_seconds=limits['lease_seconds']);self.registry.MAX_SAMPLE=min(4,limits['sample_size']);self.protocol.registry=self.registry
                self.signal_bytes=min(32768,limits['signal_bytes']);self.descriptor_token=None;self.descriptor_revision=max(old_revision+1,p['revision'])
                try:self.descriptor(renew=True)
                except Exception as error:
                    self.authorized=False;self.registry.close();failure=error
            else:self.descriptor_token=previous
            if failure is None and publish is not None:
                try:publish(self.bundle())
                except Exception as error:
                    self.authorized=False;self.registry.close();failure=error
        await asyncio.gather(*(ws.close(1012 if self.authorized else 1008,'unavailable') for ws,_ in list(self.clients.values())),return_exceptions=True)
        if failure is not None:raise failure
        return True
    def bundle(self,renew_if_expiring=False):
        with self.descriptor_lock:
            token=self.descriptor(renew_if_expiring=renew_if_expiring) if self.authorized else self.descriptor_token or ''
            return {'version':'codi-bootstrap-bundle/1','seed':self.seed,'descriptor':token}
    def quota(self,kind,size=0,ws=None):
        now=self.clock()
        if kind=='start':
            self.starts[:]=[v for v in self.starts if v[0]>now-60]
            if len(self.starts)>=self.MAX_STARTS_PER_MINUTE:raise ValueError('connection rate')
            self.starts.append((now,0));return
        if kind not in ('egress','frame') or ws is None or type(size) is not int or size<0:raise ValueError('invalid quota request')
        local,global_window=(self.socket_frame_egress.setdefault(ws,EgressWindow(4096,16*1024*1024)),self.frame_egress) if kind=='frame' else (self.socket_egress.setdefault(ws,EgressWindow(128,1024*1024)),self.egress)
        local.prune(now);global_window.prune(now)
        if not local.allows(size) or not global_window.allows(size):raise ValueError('egress rate')
        local.add(now,size);global_window.add(now,size)
    async def send(self,ws,token,*,frame=False):
        self.ensure_authority();generation=self.policy_generation
        self.quota('frame' if frame else 'egress',len(token.encode('utf-8')),ws);lock=self.send_locks.setdefault(ws,asyncio.Lock())
        async def ordered():
            async with lock:
                self.ensure_authority()
                if generation!=self.policy_generation:raise ValueError('Policy changed during send')
                await ws.send(token)
        await asyncio.wait_for(ordered(),2)
    async def set_anonymous_allowed(self,allowed):
        if type(allowed) is not bool:raise ValueError('Boolean anonymous policy required')
        self.anonymous_allowed=allowed
        if not allowed:
            clients=[ws for ws,connection in list(self.clients.values()) if connection.public and connection.public.get('kind')=='anonymous']
            await asyncio.gather(*(ws.close(1013,'anonymous introductions disabled') for ws in clients),return_exceptions=True)

    async def handler(self,ws):
        connection=None
        try:
            self.ensure_authority()
            if ws.request.path!=self.request_path or self.active>=self.MAX_CONNECTIONS:await ws.close(1008,'unavailable');return
            self.active+=1
            try:
                connection=self.protocol.connect();await self.send(ws,connection.challenge())
                token=await asyncio.wait_for(ws.recv(),10)
                if not isinstance(token,str) or len(token)>24576:raise ValueError('auth size')
                response=connection.authenticate(token)
                if not self.anonymous_allowed and connection.public['kind']=='anonymous':raise AnonymousIntroductionsDisabled('anonymous introductions disabled')
                await self.send(ws,response)
                if not self.anonymous_allowed and connection.public['kind']=='anonymous':raise AnonymousIntroductionsDisabled('anonymous introductions disabled')
                self.clients[connection.handle]=(ws,connection)
                while True:
                    self.registry.cleanup()
                    if connection.handle not in self.registry.owners:break
                    try:token=await asyncio.wait_for(ws.recv(),min(30,self.registry.owners[connection.handle].admission.identity_expiry-self.registry.now()))
                    except asyncio.TimeoutError:continue
                    self.ensure_authority()
                    if not self.anonymous_allowed and connection.public['kind']=='anonymous':raise AnonymousIntroductionsDisabled('anonymous introductions disabled')
                    if not isinstance(token,str) or len(token)>49152:raise ValueError('request size')
                    # Registry/signatures are synchronous and serialized on this event loop.
                    # Reject before mutation; no binary transport or generic message operation.
                    _,preview,_,_=jose.inspect(token,'codi-steward-request/1',49152)
                    body=preview.get('body')
                    if isinstance(body,dict) and 'signal' in body and (not isinstance(body['signal'],str) or len(body['signal'])>self.signal_bytes):raise ValueError('signal capacity')
                    operation=preview.get('operation')
                    if operation=='CHANNEL_ANNOUNCE' and self.offered_channels_only:
                        signed=jose.verify(token,connection.key,'codi-steward-request/1',49152);exact(signed,'version nonce sequence iat exp operation body');times(signed,self.registry.now(),30)
                        if signed['version']!='codi-steward-request/1' or signed['nonce']!=connection.nonce:raise ValueError('request binding')
                        wanted=signed['body'];accepted=False
                        try:
                            exact(wanted,'lease_id tag channel genesis_hash')
                            for field in ('lease_id','tag','channel','genesis_hash'):identifier(wanted[field])
                            if wanted['tag']!=jose.digest(jose.dumps(['codi-channel-rendezvous/1',wanted['channel'],wanted['genesis_hash']])):raise ValueError('channel tag mismatch')
                            if connection.public['kind']!='registered' or self.official_channel_allowed is None:raise ValueError('registered offered channel required')
                            accepted=(await asyncio.wait_for(self.official_channel_allowed(wanted['channel'],wanted['genesis_hash']),2)) is True
                        except Exception:accepted=False
                        self.ensure_authority()
                        if not accepted:
                            self.registry._owner(connection.handle,signed['sequence']);await self.send(ws,connection.refusal(signed['sequence'],operation));continue
                    response,forward=connection.request(token)
                    if operation=='CHANNEL_FRAME' and forward:
                        try:
                            if self.official_channel_allowed is None or (await asyncio.wait_for(self.official_channel_allowed(body['channel'],body['genesis_hash']),2)) is not True:raise ValueError('not an offered channel')
                            self.ensure_authority();self.registry.cleanup()
                            # Leases can expire while the official registry is checked.
                            source=self.registry.leases.get(body['source_id']);destination=self.registry.leases.get(body['destination_id'])
                            if not source or not destination or source.owner!=connection.handle or source.scope!=destination.scope or body['tag'] not in self.registry.channel_tags.get(body['source_id'],set()) or body['tag'] not in self.registry.channel_tags.get(body['destination_id'],set()):raise ValueError('channel route expired')
                        except Exception:
                            response=connection.refusal(preview['sequence'],operation);forward=None
                    if operation in ('INDEX_PUBLISH','INDEX_PUBLISH_BATCH','INDEX_SEARCH'):
                        try:_,accepted,_,_=jose.inspect(response,'codi-steward-response/1',49152)
                        except ValueError:accepted=None
                        if accepted is not None:
                            registry=self.registry;lease=registry._lease(connection.handle,body['lease_id']);scope=lease.scope
                            try:
                                if self.public_directory is None:raise ValueError('directory unavailable')
                                async with asyncio.timeout(10):
                                    async with self.directory_slots:
                                        if operation=='INDEX_SEARCH':
                                            value=await asyncio.to_thread(self.public_directory.search,scope,body['query'],body['after'],body['limit'])
                                        else:
                                            wires=[body['wire']] if operation=='INDEX_PUBLISH' else body['wires']
                                            await asyncio.to_thread(self.public_directory.publish,scope,wires,registry.now())
                                            value=None
                                self.ensure_authority()
                                if registry is not self.registry or not self.anonymous_allowed and connection.public['kind']=='anonymous':raise ValueError('directory admission ended')
                                registry.cleanup();registry._lease(connection.handle,body['lease_id'])
                                if operation=='INDEX_SEARCH':response=connection.response(preview['sequence'],operation,value)
                            except Exception:response=connection.refusal(preview['sequence'],operation)
                    if forward:
                        target,event,expiry=forward;destination=self.clients.get(target)
                        if destination is None:response=connection.unavailable(response)
                        else:
                            try:await self.send(destination[0],destination[1].event(event,expiry),frame=event.get('kind')=='frame')
                            except (ConnectionClosed,asyncio.TimeoutError):
                                # Delivery may be ambiguous and the event sequence
                                # was consumed. Reauthenticate the recipient rather
                                # than leaving a live control stream with a gap.
                                await destination[0].close(1013,'unavailable')
                                response=connection.unavailable(response)
                    await self.send(ws,response,frame=operation=='CHANNEL_FRAME')
            finally:
                self.active-=1
        except Unavailable:
            # Capacity or an expired admission can clear without changing credentials.
            # Close without exposing details; clients may reauthenticate with backoff.
            try:await ws.close(1013,'unavailable')
            except ConnectionClosed:pass
        except AnonymousIntroductionsDisabled:
            try:await ws.close(1013,'anonymous introductions disabled')
            except ConnectionClosed:pass
        except (Exception,):
            # No token, SDP, identity or exception text is logged or returned.
            try:await ws.close(1008,'unavailable')
            except ConnectionClosed:pass
        finally:
            if connection:
                self.clients.pop(connection.handle,None);connection.close()
            self.send_locks.pop(ws,None);self.socket_egress.pop(ws,None);self.socket_frame_egress.pop(ws,None)
    async def start(self,port=0):
        if self.server:raise ValueError('already running')
        adapter=self
        class BoundedConnection(ServerConnection):
            counted=False
            def connection_made(self,transport):
                super().connection_made(transport)
                try:
                    adapter.quota('start')
                    if adapter.wire_count>=adapter.MAX_CONNECTIONS:raise ValueError('connection capacity')
                    adapter.wire_count+=1;self.counted=True
                except ValueError:transport.abort()
            def connection_lost(self,exc):
                if self.counted:adapter.wire_count-=1;self.counted=False
                super().connection_lost(exc)
        logger=logging.getLogger('codi.steward.websocket');logger.addHandler(logging.NullHandler());logger.propagate=False
        self.server=await serve(self.handler,'127.0.0.1',port,origins=self.origins,compression=None,max_size=49152,max_queue=2,write_limit=16384,open_timeout=5,close_timeout=2,ping_interval=20,ping_timeout=10,server_header=None,create_connection=BoundedConnection,logger=logger)
        return self.server.sockets[0].getsockname()[1]
    def descriptor(self,renew=False,renew_if_expiring=False):
        with self.descriptor_lock:return self._descriptor(renew,renew_if_expiring)
    def _descriptor(self,renew,renew_if_expiring):
        self.ensure_authority();now=self.registry.now();end=min(self.registry.delegation_expiry,self.seed_payload['exp'])
        if now>=end:raise ValueError('expired service delegation')
        if self.publisher_state is not None:
            template={'version':'codi-steward/1','realm':self.protocol.realm,'key_id':self.protocol.key_id,'exp':end,'endpoint':self.protocol.endpoint,'scopes':list(self.grant['scopes']),'limits':{'lease_seconds':self.registry.lease_seconds,'sample_size':self.registry.MAX_SAMPLE,'signal_bytes':self.signal_bytes}}
            token=self.publisher_state.publish(template,self.protocol.key,self.seed_payload,now=now,minimum_revision=self.seed_payload['revision'],renew=renew,renew_if_expiring=renew_if_expiring)
            self.descriptor_token=token;self.descriptor_revision=jose.inspect(token,'codi-steward/1',8192)[1]['revision'];return token
        if self.descriptor_token and renew_if_expiring:
            _,old,_,_=jose.inspect(self.descriptor_token,'codi-steward/1',8192)
            renew=old['exp']-now<=60 and old['exp']<end
        if self.descriptor_token and not renew:return self.descriptor_token
        revision=self.descriptor_revision+(1 if self.descriptor_token else 0)
        if revision>2**53-1:raise ValueError('descriptor revision limit')
        issued=now if renew else self.seed_payload['iat']
        token=self.protocol.sign({'version':'codi-steward/1','realm':self.protocol.realm,'key_id':self.protocol.key_id,'revision':revision,'iat':issued,'exp':min(issued+300,end),'endpoint':self.protocol.endpoint,'scopes':list(self.grant['scopes']),'limits':{'lease_seconds':self.registry.lease_seconds,'sample_size':self.registry.MAX_SAMPLE,'signal_bytes':self.signal_bytes}},'codi-steward/1')
        self.descriptor_token=token;self.descriptor_revision=revision;return token
    async def close(self):
        if self.server:self.server.close();await self.server.wait_closed();self.server=None
        self.registry.close()
        if self.public_directory:self.public_directory.close()
