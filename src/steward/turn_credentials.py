"""Coturn's documented TURN REST credentials; no public issuance endpoint.

HMAC-SHA1 is required by Coturn's existing profile, not used for identity signing.
Keep the shared secret only in native private state. TURN expiry gates new auth;
it is not an assertion of instant termination of established allocations.
"""
import base64,hashlib,hmac,secrets,time


def mint(secret, *, lifetime_seconds=300, clock=time.time, not_after=None):
    if not isinstance(secret, bytes) or not 32 <= len(secret) <= 128:
        raise ValueError('A private 32..128 byte TURN secret is required')
    if type(lifetime_seconds) is not int or not 15 <= lifetime_seconds <= 600:
        raise ValueError('TURN lifetime must be 15..600 seconds')
    now = int(clock())
    deadline = now + lifetime_seconds
    if not_after is not None:
        if type(not_after) is not int:
            raise ValueError('Invalid authorization deadline')
        deadline = min(deadline, not_after)
    if deadline <= now:
        raise ValueError('TURN authorization expired')
    username = str(deadline) + ':' + secrets.token_urlsafe(18)
    credential = base64.b64encode(hmac.new(secret, username.encode('ascii'), hashlib.sha1).digest()).decode('ascii')
    return {'username': username, 'credential': credential,
            'credentialType': 'password', 'expiresAt': deadline}
