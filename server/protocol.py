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
