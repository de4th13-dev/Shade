"""Server-side Shade configuration. Client never receives this file."""
from __future__ import annotations

import json
import os
import ipaddress
import tempfile
from copy import deepcopy
from pathlib import Path
from urllib.parse import urlsplit

from protocol import normalize_origin

HERE = Path(__file__).resolve().parent
CONFIG_PATH = Path(os.environ.get('SHADE_SERVER_CONFIG', str(HERE / 'config.json'))).expanduser().resolve()
PID_PATH = Path(os.environ.get('SHADE_PID_FILE', str(HERE / 'shade.pid'))).expanduser().resolve()

DEFAULT = {
    'version': 2,
    'gateway': {
        'bind_host': '127.0.0.1',
        'bind_port': 8080,
        'public_url': 'http://127.0.0.1:8080',
        'tls': {'mode': 'off', 'cert_file': '', 'key_file': ''},
    },
    'backends': {'public': 'http://127.0.0.1:9001', 'hidden': 'http://127.0.0.1:9002'},
    'auth': {'scheme': 'serenity-opaque-1.1.0', 'server_setup': '', 'password_file': '', 'credential_id': 'shade-default'},
    'limits': {'request_body_bytes': 2097152, 'upstream_timeout_seconds': 20,
               'session_ttl_seconds': 1800},
}


def backend_url(raw: str) -> str:
    """Normalize a fixed upstream origin (no paths/queries/credentials)."""
    raw = str(raw).strip()
    p = urlsplit(raw)
    if p.scheme not in ('http', 'https') or not p.hostname or p.username or p.password:
        raise ValueError('Backend must be an http:// or https:// URL without credentials')
    if p.path not in ('', '/') or p.query or p.fragment:
        raise ValueError('Backend address must not include a path, query or fragment')
    try:
        port = p.port
    except ValueError as ex:
        raise ValueError('Invalid backend port') from ex
    if port is not None and not 1 <= port <= 65535:
        raise ValueError('Backend port out of range')
    hostname = p.hostname.lower()
    try:
        ip = ipaddress.ip_address(hostname)
        hostname = f'[{ip.compressed}]' if ip.version == 6 else ip.compressed
    except ValueError:
        hostname = hostname.encode('idna').decode('ascii')
    if not hostname or any(x in hostname for x in ('/', '@', '\\')):
        raise ValueError('Invalid backend hostname')
    return f'{p.scheme}://{hostname}' + (f':{port}' if port else '')


def is_loopback(host: str) -> bool:
    if host.lower() == 'localhost':
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def validate(config: dict, *, require_key: bool = True) -> dict:
    """Return a normalized deep copy; validate BEFORE changing listeners."""
    c = deepcopy(config)
    if c.get('version') != 2:
        raise ValueError('Unsupported config.json version')
    g, b, auth, lim = (c['gateway'], c['backends'], c['auth'], c['limits'])
    bind = str(g['bind_host']).strip()
    if not bind or bind == 'localhost':
        raise ValueError('Use a numeric bind address, e.g. 127.0.0.1 or 0.0.0.0')
    try:
        ipaddress.ip_address(bind)
    except ValueError as ex:
        raise ValueError('Gateway bind_host must be a numeric IP address') from ex
    port = g['bind_port']
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('Gateway bind_port must be between 1 and 65535')
    origin = normalize_origin(g['public_url'])
    g['public_url'] = origin
    g['bind_host'] = bind
    tls = g['tls']
    mode = tls['mode']
    if mode not in ('off', 'direct', 'reverse_proxy'):
        raise ValueError('TLS mode must be off, direct or reverse_proxy')
    if mode == 'off':
        if not is_loopback(bind) or not origin.startswith('http://') or not is_loopback(urlsplit(origin).hostname):
            raise ValueError('Plain HTTP is allowed only on loopback with a local HTTP origin')
    elif mode == 'reverse_proxy':
        if not is_loopback(bind) or not origin.startswith('https://'):
            raise ValueError('Reverse-proxy TLS requires a loopback bind address and HTTPS public_url')
    elif mode == 'direct':
        if not origin.startswith('https://'):
            raise ValueError('Direct TLS requires an HTTPS public_url')
        for key in ('cert_file', 'key_file'):
            value = str(tls.get(key, '')).strip()
            if not value:
                raise ValueError('TLS certificate and private key paths are required')
            file = Path(value).expanduser()
            if not file.is_absolute():
                file = HERE / file
            if not file.is_file():
                raise ValueError(f'TLS file does not exist: {file}')
            tls[key] = str(file.resolve())
    b['public'] = backend_url(b['public'])
    b['hidden'] = backend_url(b['hidden'])
    if b['public'] == b['hidden']:
        raise ValueError('Public and hidden backend must be different')
    for role, target in b.items():
        loc = urlsplit(target)
        target_port = loc.port or (443 if loc.scheme == 'https' else 80)
        # Stop obvious loops to the public hostname or to the local listener.
        if target == origin or (target_port == port and is_loopback(loc.hostname)
                                and (is_loopback(bind) or bind in ('0.0.0.0', '::'))):
            raise ValueError(f'{role} backend points back to the Gateway listener')
    if auth.get('scheme') != 'serenity-opaque-1.1.0':
        raise ValueError('OPAQUE credentials required; run python server.py set-password')
    if auth.get('credential_id') != 'shade-default':
        raise ValueError('Unsupported OPAQUE credential identifier')
    for field in ('server_setup', 'password_file'):
        value = auth.get(field, '')
        if not isinstance(value, str) or len(value) > 8192:
            raise ValueError('Invalid OPAQUE credential field')
        if require_key and not value:
            raise ValueError('OPAQUE not configured; run python server.py set-password')
    if bool(auth.get('server_setup')) != bool(auth.get('password_file')):
        raise ValueError('Incomplete OPAQUE server configuration')
    bounds = {'request_body_bytes': (1024, 64 * 1024 * 1024),
              'upstream_timeout_seconds': (1, 300), 'session_ttl_seconds': (60, 86400)}
    for name, (minimum, maximum) in bounds.items():
        value = lim[name]
        if type(value) is not int or not minimum <= value <= maximum:
            raise ValueError(f'{name} must be between {minimum} and {maximum}')
    return c


def load(*, require_key: bool = True) -> dict:
    with CONFIG_PATH.open(encoding='utf-8') as f:
        return validate(json.load(f), require_key=require_key)


def save(config: dict) -> None:
    c = validate(config, require_key=False)
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix='.shade-config-', suffix='.tmp', dir=CONFIG_PATH.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            if os.name == 'posix':
                os.fchmod(f.fileno(), 0o600)
            json.dump(c, f, indent=2, ensure_ascii=False)
            f.write('\n')
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, CONFIG_PATH)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def change_password(config: dict, password: str) -> dict:
    """Local-only admin registration: never accept remote registrations."""
    if len(password) < 12:
        raise ValueError('Password must be at least 12 characters')
    import opaque_adapter as opaque
    result = deepcopy(config)
    result['version'] = 2
    setup, password_file = opaque.register(password)
    result['auth'] = {
        'scheme': 'serenity-opaque-1.1.0',
        'server_setup': setup,
        'password_file': password_file,
        'credential_id': 'shade-default',
    }
    return validate(result)


def load_existing_or_default() -> dict:
    if CONFIG_PATH.exists():
        with CONFIG_PATH.open(encoding='utf-8') as f:
            return json.load(f)
    return deepcopy(DEFAULT)
