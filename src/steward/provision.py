"""Strict root-signed public seed validation, independent of runtime admission."""
import re
from urllib.parse import urlsplit
from .protocol import jose,exact,times,identifier

def verified_seed(token,root_key,realm,now):
    p=jose.verify(token,root_key,'codi-seed/1',32768);exact(p,'version realm revision iat exp stewards');times(p,now,86400);identifier(realm)
    if p['version']!='codi-seed/1' or p['realm']!=realm or type(p['revision']) is not int or not 1<=p['revision']<=2**53-1 or not isinstance(p['stewards'],list) or not 1<=len(p['stewards'])<=8:raise ValueError('seed')
    seen=set()
    for grant in p['stewards']:
        exact(grant,'key_id public_key endpoints scopes limits exp failure_domain');identifier(grant['key_id'])
        if jose.thumbprint(grant['public_key'])!=grant['key_id'] or grant['key_id'] in seen:raise ValueError('delegated key')
        seen.add(grant['key_id'])
        if not isinstance(grant['endpoints'],list) or not 1<=len(grant['endpoints'])<=2 or len(set(grant['endpoints']))!=len(grant['endpoints']):raise ValueError('endpoints')
        for endpoint in grant['endpoints']:
            if not isinstance(endpoint,str) or len(endpoint)>256:raise ValueError('endpoint')
            u=urlsplit(endpoint)
            if not u.netloc or not u.path or u.username or u.password or u.query or u.fragment or u.scheme not in ('ws','wss') or (u.scheme=='ws' and u.hostname not in ('127.0.0.1','::1')):raise ValueError('endpoint')
            u.port # Validate numeric port range without contacting a destination.
        if not isinstance(grant['scopes'],list) or not 1<=len(grant['scopes'])<=16 or len(set(grant['scopes']))!=len(grant['scopes']):raise ValueError('scopes')
        for scope in grant['scopes']:identifier(scope)
        if type(grant['exp']) is not int or not now<grant['exp']<=p['exp']:raise ValueError('delegation expiry')
        if not isinstance(grant['failure_domain'],str) or not re.fullmatch(r'[A-Za-z0-9._-]{1,64}',grant['failure_domain']):raise ValueError('failure domain')
        limits=grant['limits'];exact(limits,'lease_seconds sample_size signal_bytes')
        if any(type(v) is not int for v in limits.values()) or not 1<=limits['lease_seconds']<=300 or not 1<=limits['sample_size']<=16 or not 1024<=limits['signal_bytes']<=262144:raise ValueError('capacity grant')
    return p
