"""Optional private durable publisher ledger. No keys, leases or accounts stored.

Initialize explicitly before first publication for a provisioned signing key.
Opening missing, corrupt or mismatched state never resets its revision floor.
"""
from contextlib import contextmanager
from pathlib import Path
import os
import sqlite3
import stat
from urllib.parse import quote
from .protocol import jose

class PublisherFrozen(ValueError):pass

class PublisherState:
    @classmethod
    def initialize(cls,directory):
        directory=Path(directory).absolute();directory.mkdir(mode=0o700,exist_ok=False)
        db=directory/'publisher.sqlite3';fd=os.open(db,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600);os.close(fd)
        try:
            with sqlite3.connect(db) as connection:
                connection.execute('PRAGMA synchronous=FULL')
                connection.execute('CREATE TABLE publisher (id INTEGER PRIMARY KEY CHECK(id=1), binding TEXT NOT NULL, seed_revision INTEGER NOT NULL, seed_hash TEXT NOT NULL, revision INTEGER NOT NULL, token TEXT, frozen INTEGER NOT NULL)')
                connection.execute("INSERT INTO publisher VALUES (1,'UNBOUND',0,'',0,NULL,0)")
                connection.execute('PRAGMA user_version=1')
            return cls(directory)
        except BaseException:
            # Preserve failed initialization for inspection; never silently recreate.
            raise
    def __init__(self,directory):
        self.directory=Path(directory).absolute();self.db=self.directory/'publisher.sqlite3'
        self._check()
    def _check(self):
        for path,mode,directory in [(self.directory,0o700,True),(self.db,0o600,False)]:
            info=path.lstat()
            if info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=mode or (not stat.S_ISDIR(info.st_mode) if directory else not stat.S_ISREG(info.st_mode)) or (not directory and (info.st_nlink!=1 or info.st_size>1048576)):raise ValueError('Publisher state permissions or file type')
        journal=Path(str(self.db)+'-journal')
        try:info=journal.lstat()
        except FileNotFoundError:info=None
        if info is not None:
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or info.st_size>1048576:raise ValueError('Publisher journal permissions or file type')
        for suffix in ('-wal','-shm'):
            unexpected=Path(str(self.db)+suffix)
            if unexpected.exists() or unexpected.is_symlink():raise ValueError('Unexpected publisher journal mode')
    @contextmanager
    def transaction(self):
        self._check()
        connection=sqlite3.connect('file:'+quote(str(self.db),safe='/')+'?mode=rw',uri=True,timeout=2,isolation_level=None)
        try:
            connection.execute('PRAGMA synchronous=FULL');connection.execute('PRAGMA journal_mode=DELETE')
            if connection.execute('PRAGMA user_version').fetchone()[0]!=1:raise ValueError('Publisher state version')
            connection.execute('BEGIN IMMEDIATE')
            yield connection
            connection.execute('COMMIT') # Publish only after this durable commit returns.
        except BaseException:
            if connection.in_transaction:connection.execute('ROLLBACK')
            raise
        finally:connection.close()
    def bind(self,binding,seed):
        binding=jose.dumps(binding);digest=jose.digest(jose.dumps(seed));fork=False
        with self.transaction() as db:
            row=db.execute('SELECT binding,seed_revision,seed_hash,revision,token,frozen FROM publisher WHERE id=1').fetchone()
            if row is None:raise ValueError('Missing publisher state row')
            if row[5]:raise PublisherFrozen('Publisher authority is frozen')
            if row[:5]==('UNBOUND',0,'',0,None):db.execute('UPDATE publisher SET binding=?,seed_revision=?,seed_hash=? WHERE id=1',(binding,seed['revision'],digest))
            else:
                if row[0]!=binding:raise ValueError('Publisher provisioning mismatch')
                if seed['revision']<row[1]:raise ValueError('Persisted seed rollback')
                if seed['revision']==row[1] and digest!=row[2]:
                    db.execute('UPDATE publisher SET frozen=1 WHERE id=1');fork=True
                elif seed['revision']>row[1]:db.execute('UPDATE publisher SET seed_revision=?,seed_hash=? WHERE id=1',(seed['revision'],digest))
        if fork:raise PublisherFrozen('Persisted authenticated seed fork')
    def assert_seed(self,seed):
        with self.transaction() as db:
            row=db.execute('SELECT seed_revision,seed_hash,frozen FROM publisher WHERE id=1').fetchone()
            if row is None:raise ValueError('Missing publisher state')
            if row[2]:raise PublisherFrozen('Publisher authority is frozen')
            if row[0]!=seed['revision'] or row[1]!=jose.digest(jose.dumps(seed)):raise ValueError('Runtime seed is not current')
    def publish(self,template,key,seed,*,now,minimum_revision,renew=False,renew_if_expiring=False):
        """Serialize sign+commit across threads/processes, then return cached wire bytes."""
        public=jose.public_jwk(key)
        with self.transaction() as db:
            row=db.execute('SELECT revision,token,binding,seed_revision,seed_hash,frozen FROM publisher WHERE id=1').fetchone()
            if row is None:raise ValueError('Publisher must be bound before publication')
            revision,token,binding,seed_revision,seed_hash,frozen=row;old=None
            if frozen or seed_revision!=seed['revision'] or seed_hash!=jose.digest(jose.dumps(seed)):raise ValueError('Publisher seed changed or frozen')
            binding=jose.loads(binding)
            if binding['realm']!=template['realm'] or binding['service_key_id']!=jose.thumbprint(public) or binding['endpoint']!=template['endpoint']:raise ValueError('Publisher signing binding mismatch')
            if token is not None:
                old=jose.verify(token,public,'codi-steward/1',8192)
                if type(revision) is not int or type(old.get('revision')) is not int or old.get('revision')!=revision or not 1<=revision<=2**53-1:raise ValueError('Publisher revision/token mismatch')
                if set(old)!=set(template)|{'revision','iat'}:raise ValueError('Persisted descriptor schema')
                same=all(old[k]==v for k,v in template.items() if k!='exp')
                fresh=type(old['iat']) is int and type(old['exp']) is int and old['iat']<=now+30 and now<old['exp']<=template['exp'] and 0<old['exp']-old['iat']<=300
                near=renew_if_expiring and old['exp']-now<=60 and old['exp']<template['exp']
                if same and fresh and revision>=minimum_revision and not renew and not near:return token
            elif revision!=0:raise ValueError('Missing persisted descriptor')
            revision=max(revision+1,minimum_revision)
            if not 1<=revision<=2**53-1:raise ValueError('Publisher revision limit')
            payload={**template,'revision':revision,'iat':now,'exp':min(now+300,template['exp'])}
            token=jose.sign(payload,key,'codi-steward/1')
            db.execute('UPDATE publisher SET revision=?,token=? WHERE id=1',(revision,token))
        return token

class PublicChannelDirectory:
    """Durable public references only; no channel content or private keys.

    Call on a worker thread, not the signaling event loop. Entries are accepted
    only while their owner's listing is signed and fresh; stored proofs remain
    verifiable using their recorded admission time after their lease expires.
    """
    def __init__(self, directory=None):
        import secrets
        self._anchor=None;created=True
        if directory is None:
            self._uri='file:codi-directory-'+secrets.token_hex(16)+'?mode=memory&cache=shared';self._anchor=sqlite3.connect(self._uri,uri=True,check_same_thread=False)
        else:
            directory=Path(directory).absolute();info=directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError('Invalid channel directory state path')
            path=directory/'public-channels.sqlite3'
            try:fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600);os.close(fd)
            except FileExistsError:created=False
            info=path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600:raise ValueError('Invalid public channel directory file')
            self._uri=path.as_uri()+'?mode=rw'
        with self._connect() as db:
            db.execute('PRAGMA synchronous=FULL')
            if created:
                db.execute('BEGIN IMMEDIATE')
                try:
                    db.execute('CREATE TABLE channel_directory (scope TEXT NOT NULL, channel TEXT NOT NULL, genesis TEXT NOT NULL, wire TEXT NOT NULL, label TEXT NOT NULL, description TEXT NOT NULL, issued INTEGER NOT NULL, verified_at INTEGER NOT NULL, last_seen INTEGER NOT NULL, PRIMARY KEY(scope,channel))')
                    db.execute('CREATE INDEX channel_directory_order ON channel_directory(scope,issued DESC,channel)')
                    db.execute('PRAGMA user_version=1');db.execute('COMMIT')
                except BaseException:db.execute('ROLLBACK');raise
            if db.execute('PRAGMA user_version').fetchone()!=(1,) or [r[1] for r in db.execute('PRAGMA table_info(channel_directory)')]!=['scope','channel','genesis','wire','label','description','issued','verified_at','last_seen']:raise ValueError('Public channel directory schema is invalid; retain it for recovery')
    @contextmanager
    def _connect(self):
        db=sqlite3.connect(self._uri,uri=True,timeout=5,isolation_level=None)
        db.create_function('codi_casefold',1,lambda value:value.casefold(),deterministic=True)
        try:yield db
        finally:db.close()
    def publish(self,scope,wires,now):
        from .protocol import identifier,verify_listing,_proof
        identifier(scope)
        if not isinstance(wires,list) or not 1<=len(wires)<=4 or type(now) is not int:raise ValueError('Invalid directory publication')
        records=[(wire,verify_listing(wire,now)) for wire in wires]
        for _,value in records:
            policy=_proof(value['policyWire'],value['channel'])
            if policy.get('stream')!='chat' or policy.get('publicRead') is not True:raise ValueError('Only public chat references may be listed')
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                for wire,value in records:
                    old=db.execute('SELECT genesis,wire,label,description,issued,verified_at,last_seen FROM channel_directory WHERE scope=? AND channel=?',(scope,value['channel'])).fetchone()
                    if old and old[0]!=value['genesisHash']:raise ValueError('Channel policy changed')
                    if old and value['issued']<old[4]:continue
                    if old and value['issued']==old[4] and (old[2],old[3])!=(value['label'],value['description']):raise ValueError('Conflicting same-time listing')
                    if old and value['issued']==old[4]:continue
                    db.execute('INSERT INTO channel_directory VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(scope,channel) DO UPDATE SET wire=excluded.wire,label=excluded.label,description=excluded.description,issued=excluded.issued,verified_at=excluded.verified_at,last_seen=excluded.last_seen',(scope,value['channel'],value['genesisHash'],wire,value['label'],value['description'],value['issued'],now,now))
                db.execute('COMMIT')
            except BaseException:db.execute('ROLLBACK');raise
    def search(self,scope,query,after,limit):
        from .protocol import identifier
        identifier(scope)
        if not isinstance(query,str) or len(query.encode('utf-16-le'))//2>64 or len(query.encode())>256 or not isinstance(after,str) or len(after)>64 or type(limit) is not int or not 1<=limit<=2:raise ValueError('Invalid directory query')
        before=2**53-1;channel=''
        if after:
            parts=after.split(':');
            if len(parts)!=2 or not parts[0].isascii() or not parts[0].isdecimal() or str(int(parts[0]))!=parts[0] or not 0<=int(parts[0])<=2**53-1:raise ValueError('Invalid directory cursor')
            before=int(parts[0]);channel=parts[1];identifier(channel)
        with self._connect() as db:
            rows=db.execute("SELECT channel,wire,verified_at,issued FROM channel_directory WHERE scope=? AND (issued<? OR (issued=? AND channel>?)) AND instr(codi_casefold(label || ' ' || description),?)>0 ORDER BY issued DESC,channel LIMIT ?",(scope,before,before,channel,query.strip().casefold(),limit+1)).fetchall()
        selected=rows[:limit];return {'items':[{'wire':wire,'verifiedAt':verified} for _,wire,verified,_ in selected],'next':str(selected[-1][3])+':'+selected[-1][0] if len(rows)>limit else None}
    def close(self):
        if self._anchor:self._anchor.close();self._anchor=None
