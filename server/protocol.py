"""Shared URL canonicalization; OPAQUE does not use the legacy HMAC module."""
from urllib.parse import urlsplit

def normalize_origin(raw: str) -> str:
    p = urlsplit(raw)
    if p.scheme not in ("http", "https") or not p.hostname or p.username or p.password or p.path not in ("", "/") or p.query or p.fragment:
        raise ValueError("Expected HTTP(S) origin without path/query/credentials")
    _ = p.port
    host = p.hostname.lower()
    if ':' in host and not host.startswith('['): host = '[' + host + ']'
    port = '' if p.port is None or (p.scheme == 'http' and p.port == 80) or (p.scheme == 'https' and p.port == 443) else ':' + str(p.port)
    return f"{p.scheme}://{host}{port}"


def request_origin(scheme: str, authority: str) -> str:
    """Validate an HTTP Host authority before using it as an origin or redirect."""
    import ipaddress
    import re
    if not authority or any(c.isspace() or ord(c) < 33 or ord(c) > 126 for c in authority):
        raise ValueError('Invalid Host')
    if any(c in authority for c in '/\\?#@%,'):
        raise ValueError('Invalid Host')
    if authority.startswith('['):
        match = re.fullmatch(r'\[([^\]]+)\](?::([0-9]+))?', authority)
        if not match:
            raise ValueError('Invalid IPv6 Host')
        ipaddress.IPv6Address(match[1])
    else:
        match = re.fullmatch(r'([A-Za-z0-9.-]+)(?::([0-9]+))?', authority)
        if not match or len(match[1]) > 254:
            raise ValueError('Invalid Host')
        if any(not label or len(label) > 63 or label.startswith('-') or label.endswith('-')
               for label in match[1].rstrip('.').split('.')):
            raise ValueError('Invalid Host label')
    if match[2] is not None and not 1 <= int(match[2]) <= 65535:
        raise ValueError('Invalid Host port')
    return normalize_origin(f'{scheme}://{authority}')
