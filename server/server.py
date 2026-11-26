"""Shade Gateway: external public/hidden backends, no demo websites.

Security model: failed login returns the public homepage; real public backend
must stay reachable. HTTPS direct via ssl.SSLContext or via a trusted TLS proxy.
"""
from __future__ import annotations

import argparse
import asyncio
from getpass import getpass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import ssl
import sys
import time
from urllib.parse import urlsplit

import aiohttp
from aiohttp import ClientSession, ClientTimeout, web
from yarl import URL

from protocol import normalize_origin, request_origin
from configuration import CONFIG_PATH, PID_PATH, DEFAULT, change_password, load, load_existing_or_default, save, validate

SESSION_KEY = web.AppKey('shade_upstream_http_client', ClientSession)
SESSION_COOKIE_NAMES = {'shade_session', '__Host-Shade-Session'}
AUTH_START = '/.well-known/shade-opaque/start'
AUTH_FINISH = '/.well-known/shade-opaque/finish'
LOGOUT_PATH = '/.well-known/shade-logout'
HOP_HEADERS = {'connection', 'keep-alive', 'proxy-authenticate',
               'proxy-authorization', 'te', 'trailer', 'transfer-encoding',
               'upgrade', 'host', 'content-length', 'forwarded', 'x-real-ip'}

class SessionGuard:
    """Opaque short-lived tokens. Only SHA-256 digests are stored by Gateway."""

    def __init__(self, *, max_sessions: int = 5000, ttl_seconds: int = 1800):
        self.sessions: dict[tuple[str, bytes], float] = {}
        self.max_sessions = max_sessions
        self.ttl_seconds = ttl_seconds

    @staticmethod
    def _digest(token: str) -> bytes:
        return hashlib.sha256(token.encode("ascii")).digest()

    def _prune(self):
        now = time.monotonic()
        for key, expiry in list(self.sessions.items()):
            if expiry <= now:
                del self.sessions[key]

    def issue(self, origin: str) -> str | None:
        self._prune()
        if len(self.sessions) >= self.max_sessions:
            return None
        token = secrets.token_urlsafe(32)
        self.sessions[(origin, self._digest(token))] = time.monotonic() + self.ttl_seconds
        return token

    def valid(self, token: str | None, origin: str) -> bool:
        if not token or len(token) > 256:
            return False
        try:
            digest = self._digest(token)
        except UnicodeEncodeError:
            return False
        return self.sessions.get((origin, digest), 0) > time.monotonic()

    def revoke(self, token: str, origin: str) -> None:
        try:
            self.sessions.pop((origin, self._digest(token)), None)
        except UnicodeEncodeError:
            pass


def session_safe_origin(request: web.Request, expected_origin: str | None = None) -> bool:
    """CSRF guard for cookie-authenticated unsafe methods.

    Explicit Origin must match the current request origin. Chromium can send null
    for same-origin HTML form POSTs under Referrer-Policy: no-referrer.
    Allow that case only with browser-generated same-origin navigation metadata.
    """
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return True
    if request.headers.get("Sec-Fetch-Site", "") not in ("", "same-origin", "none"):
        return False
    raw_origin = request.headers.get("Origin", "")
    if raw_origin == 'null':
        return (request.method == 'POST'
                and request.headers.get('Sec-Fetch-Site') == 'same-origin'
                and request.headers.get('Sec-Fetch-Mode') == 'navigate'
                and request.headers.get('Sec-Fetch-Dest') == 'document')
    if not raw_origin:
        return False
    try:
        parsed = urlsplit(raw_origin)
        if (parsed.scheme not in {"http", "https"} or not parsed.netloc
                or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment):
            return False
        actual = normalize_origin(raw_origin)
        expected = normalize_origin(expected_origin or f"{request.scheme}://{request.host}")
        return actual == expected
    except ValueError:
        return False


def strip_private_session_cookie(value: str) -> str:
    return "; ".join(part.strip() for part in value.split(";")
                     if part.strip() and part.strip().split("=", 1)[0] not in SESSION_COOKIE_NAMES)


class PendingOPAQUE:
    """Bounded, expiring, one-use KE2->KE3 state. Never serialize this state."""
    def __init__(self, maximum: int = 256, ttl: int = 30):
        self.max = maximum
        self.ttl = ttl
        self.data: dict[str, tuple[str, float, str]] = {}

    def add(self, state: str, origin: str) -> str | None:
        now = time.monotonic()
        for k, (_, deadline, _) in list(self.data.items()):
            if deadline <= now:
                del self.data[k]
        if len(self.data) >= self.max:
            return None
        identifier = secrets.token_urlsafe(24)
        self.data[identifier] = (state, now + self.ttl, origin)
        return identifier

    def take(self, identifier: str, origin: str) -> str | None:
        now = time.monotonic()
        state = self.data.pop(identifier, None)
        if state is None or state[1] <= now or state[2] != origin:
            return None
        return state[0]


def create_gateway_app(auth: dict, public_url: str, hidden_url: str,
                       *, tls_mode: str | None = None, max_body: int = 2097152,
                       timeout_seconds: int = 20, session_ttl: int = 1800,
                       opaque_lib=None) -> web.Application:
    """OPAQUE authenticated reverse proxy, no old HMAC fallback."""
    if opaque_lib is None:
        import opaque_adapter as opaque_lib
    app = web.Application(client_max_size=max_body)
    sessions = SessionGuard(ttl_seconds=session_ttl)
    pending = PendingOPAQUE()
    if tls_mode not in (None, "off", "direct", "reverse_proxy"):
        raise ValueError("Invalid TLS mode")
    auth_paths = {AUTH_START, AUTH_FINISH}
    # Denial-of-service bound for computationally expensive OPAQUE KE1.
    throttle: dict[str, list[float]] = {}

    def admission(ip: str) -> bool:
        now = time.monotonic()
        if len(throttle) >= 4096:
            for key, ticks in list(throttle.items()):
                keep = [t for t in ticks if t > now - 60]
                if keep: throttle[key] = keep
                else: throttle.pop(key, None)
            if ip not in throttle and len(throttle) >= 4096:
                return False
        ticks = [t for t in throttle.get(ip, []) if t > now - 60]
        if len(ticks) >= 20:
            throttle[ip] = ticks
            return False
        ticks.append(now)
        throttle[ip] = ticks
        return True

    async def session_context(app: web.Application):
        app[SESSION_KEY] = ClientSession(timeout=ClientTimeout(total=timeout_seconds), auto_decompress=False,
                                         cookie_jar=aiohttp.DummyCookieJar())
        yield
        await app[SESSION_KEY].close()

    app.cleanup_ctx.append(session_context)

    async def gateway(request: web.Request) -> web.Response:
        is_auth = request.method == 'POST' and request.path in auth_paths
        payload = await request.read()
        # The TLS mode is server-controlled. Never trust X-Forwarded-* from clients.
        scheme = ('https' if tls_mode in ('direct', 'reverse_proxy') else
                  'http' if tls_mode == 'off' else request.scheme)
        try:
            hosts = request.headers.getall('Host', [])
            if len(hosts) != 1:
                raise ValueError('Expected exactly one Host')
            canonical_origin = request_origin(scheme, hosts[0])
        except ValueError:
            return web.Response(status=400, text='Bad Request')
        if is_auth and admission(request.remote or 'unknown') and len(payload) <= 8192:
            try:
                obj = json.loads(payload)
                if not isinstance(obj, dict): raise ValueError('Invalid auth request')
                if request.path == AUTH_START:
                    message = obj['ke1']
                    if not isinstance(message, str) or len(message) > 4096: raise ValueError('Bad KE1')
                    # Both endpoints use the same pinned OPAQUE library.
                    response, server_state = await asyncio.to_thread(opaque_lib.login,
                        auth['server_setup'], auth['password_file'], message, auth['credential_id'])
                    attempt = pending.add(server_state, canonical_origin)
                    if attempt is not None:
                        return web.json_response({'shade_opaque': 'v1', 'ke2': response, 'attempt': attempt},
                            headers={'Cache-Control': 'no-store', 'Pragma': 'no-cache'})
                else:
                    attempt, message = obj['attempt'], obj['ke3']
                    if not all(isinstance(v, str) for v in (attempt, message)) or len(attempt) > 128 or len(message) > 4096:
                        raise ValueError('Bad KE3')
                    server_state = pending.take(attempt, canonical_origin)
                    if server_state is not None:
                        # This verifies the client's KE3 authenticator. A failed
                        # MAC raises, and MUST NOT issue a browser session.
                        verified = await asyncio.to_thread(opaque_lib.login_finish, message, server_state)
                        if verified is not True:
                            raise RuntimeError("OPAQUE verification failed")
                        token = sessions.issue(canonical_origin)
                        if token is not None:
                            return web.json_response(
                                {'shade_authenticated': True, 'session_token': token, 'expires_in': session_ttl},
                                headers={'Cache-Control': 'no-store', 'Pragma': 'no-cache'})
            except (ValueError, KeyError, TypeError, RuntimeError, OverflowError):
                pass
            except Exception:
                # Native library may raise its own exception type; log no secrets.
                pass
            # All invalid login packets use the public homepage fallback.

        if request.raw_path == LOGOUT_PATH and request.method == 'POST':
            token = request.headers.get('X-Shade-Session', '')
            if sessions.valid(token, canonical_origin):
                sessions.revoke(token, canonical_origin)
                return web.json_response({'logged_out': True}, headers={'Cache-Control': 'no-store'})
        names = ('__Host-Shade-Session', 'shade_session') if (canonical_origin or '').startswith('https:') else ('shade_session', '__Host-Shade-Session')
        cookie = next((request.cookies[name] for name in names if name in request.cookies), None)
        valid_session = sessions.valid(cookie, canonical_origin)
        via_cookie = valid_session and session_safe_origin(request, canonical_origin)
        # A real, authenticated session with an unsafe origin is a CSRF failure,
        # not an unauthenticated request. Never forward its credentials/body to public.
        if not is_auth and valid_session and not via_cookie:
            return web.Response(status=403, text='Forbidden', headers={'Cache-Control': 'no-store'})
        authorized = not is_auth and via_cookie
        upstream = hidden_url if authorized else public_url
        proxy_method = 'GET' if is_auth else request.method
        proxy_path = '/' if is_auth else request.raw_path
        claimed_private = (bool(set(request.cookies).intersection(SESSION_COOKIE_NAMES))
                           or any(h.lower().startswith('x-shade-') for h in request.headers))
        forwarded_payload = (b'' if is_auth or (claimed_private and not authorized
                             and request.method not in {'GET', 'HEAD', 'OPTIONS'}) else payload)
        named_by_connection = {x.strip().lower() for x in request.headers.get('Connection', '').split(',')}
        incoming = {name: value for name, value in request.headers.items()
                    if name.lower() not in HOP_HEADERS | named_by_connection
                    and not name.lower().startswith('x-shade-')
                    and name.lower() != 'cookie'
                    and not name.lower().startswith('x-forwarded-')}
        if is_auth:
            for name in list(incoming):
                if name.lower() in {'content-type', 'content-encoding', 'origin', 'referer'}:
                    del incoming[name]
        forwarded_cookies = strip_private_session_cookie(request.headers.get('Cookie', ''))
        if forwarded_cookies:
            incoming['Cookie'] = forwarded_cookies
        try:
            target = URL(upstream.rstrip('/') + proxy_path, encoded=True)
            async with app[SESSION_KEY].request(
                proxy_method, target, headers=incoming, data=forwarded_payload,
                allow_redirects=False,
            ) as response:
                data = await response.read()
                response_hop = {x.strip().lower() for x in response.headers.get('Connection', '').split(',')}
                filtered = [(name, value) for name, value in response.headers.items()
                    if name.lower() not in HOP_HEADERS | response_hop
                    and name.lower() not in ('server', 'date')
                    and (not authorized or name.lower() not in {
                        'access-control-allow-origin', 'access-control-allow-credentials',
                        'access-control-allow-methods', 'access-control-allow-headers',
                        'access-control-expose-headers', 'timing-allow-origin'})
                    and not (name.lower() == 'set-cookie' and value.split('=', 1)[0] in SESSION_COOKIE_NAMES)]
                result = web.Response(body=data, status=response.status)
                for name, value in filtered:
                    if name.lower() == 'location':
                        try:
                            loc = urlsplit(value); back = urlsplit(upstream)
                            if loc.scheme in ('http', 'https') and loc.netloc.lower() == back.netloc.lower() and canonical_origin:
                                value = canonical_origin + (loc.path or '/') + (('?' + loc.query) if loc.query else '') + (('#' + loc.fragment) if loc.fragment else '')
                        except ValueError:
                            pass
                    result.headers.add(name, value)
                result.headers['Cache-Control'] = 'no-store'
                result.headers['Vary'] = 'Cookie'
                result.headers.add('Content-Security-Policy', "worker-src 'none'; frame-ancestors 'none'")
                return result
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
            return web.Response(status=502, text='Bad Gateway')

    app.router.add_route('*', '/{path:.*}', gateway)
    return app



def build_tls_context(config: dict) -> ssl.SSLContext | None:
    tls = config['gateway']['tls']
    if tls['mode'] != 'direct':
        return None
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.options |= ssl.OP_NO_COMPRESSION
    context.set_alpn_protocols(['http/1.1'])
    context.load_cert_chain(tls['cert_file'], tls['key_file'])
    return context


async def start_gateway(config: dict) -> web.AppRunner:
    """One listener only. Both public/private sites are external backends."""
    config = validate(config)
    g, b, limits = config['gateway'], config['backends'], config['limits']
    context = build_tls_context(config)
    import opaque_adapter
    await asyncio.to_thread(opaque_adapter.check)
    app = create_gateway_app(
        config['auth'], b['public'], b['hidden'], tls_mode=g['tls']['mode'],
        max_body=limits['request_body_bytes'],
        timeout_seconds=limits['upstream_timeout_seconds'],
        session_ttl=limits['session_ttl_seconds'],
    )
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    try:
        site = web.TCPSite(runner, g['bind_host'], g['bind_port'], ssl_context=context)
        await site.start()
    except Exception:
        await runner.cleanup()
        raise
    print(f"Shade Gateway running at {g['bind_host']}:{g['bind_port']} "
          f"(TLS: {g['tls']['mode']})", flush=True)
    print(f"Public backend: {b['public']}", flush=True)
    print(f"Hidden backend: {b['hidden']}", flush=True)
    return runner


def _process_start_ticks(pid: int) -> str | None:
    """Linux PID starttime (field 22), preventing signals to reused PIDs."""
    if not sys.platform.startswith('linux'):
        return None
    try:
        stat = (Path('/proc') / str(pid) / 'stat').read_text()
        return stat.rsplit(')', 1)[1].strip().split()[19]
    except (OSError, IndexError):
        return None


def _owned_live_pid() -> int | None:
    try:
        record = json.loads(PID_PATH.read_text(encoding='ascii'))
        pid = int(record['pid'])
    except (ValueError, OSError, KeyError, TypeError):
        return None
    if pid <= 0:
        return None
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return None
    except PermissionError:
        raise RuntimeError('The PID belongs to a process that you cannot control')
    if sys.platform.startswith('linux'):
        if _process_start_ticks(pid) != record.get('start_ticks'):
            return None
        try:
            cmdline = (Path('/proc') / str(pid) / 'cmdline').read_bytes().replace(b'\x00', b' ').decode(errors='replace')
        except OSError:
            return None
        if 'server.py' not in cmdline:
            raise RuntimeError(f'PID {pid} no longer appears to be a Shade server')
    return pid


def _acquire_pid() -> None:
    PID_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(PID_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        if _owned_live_pid():
            raise RuntimeError('Shade already running; use python server.py restart')
        PID_PATH.unlink(missing_ok=True)
        fd = os.open(PID_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump({'pid': os.getpid(), 'start_ticks': _process_start_ticks(os.getpid())}, f)
        f.write('\n')


def _release_pid() -> None:
    try:
        record = json.loads(PID_PATH.read_text())
        if int(record['pid']) == os.getpid() and record.get('start_ticks') == _process_start_ticks(os.getpid()):
            PID_PATH.unlink()
    except (ValueError, KeyError, TypeError, OSError):
        pass


async def serve() -> None:
    _acquire_pid()
    current_runner: web.AppRunner | None = None
    current_config: dict | None = None
    reload_signal, stop_signal = asyncio.Event(), asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum, callback in ((signal.SIGHUP, reload_signal.set),
                             (signal.SIGINT, stop_signal.set), (signal.SIGTERM, stop_signal.set)):
        try:
            loop.add_signal_handler(signum, callback)
        except NotImplementedError:
            pass
    try:
        current_config = load()
        current_runner = await start_gateway(current_config)
        while True:
            stopping = asyncio.create_task(stop_signal.wait())
            reloading = asyncio.create_task(reload_signal.wait())
            done, pending = await asyncio.wait([stopping, reloading], return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            if stopping in done or stop_signal.is_set():
                break
            reload_signal.clear()
            try:
                new_config = load()
                build_tls_context(new_config)  # Validate TLS material *before* shutdown.
            except (OSError, ValueError, KeyError, json.JSONDecodeError, ssl.SSLError) as ex:
                print(f'Cannot reload config: {ex}; old listener stays active', file=sys.stderr)
                continue
            print('Restarting Gateway (active sessions will be revoked)...', flush=True)
            assert current_runner is not None
            await current_runner.cleanup()
            current_runner = None
            try:
                current_runner = await start_gateway(new_config)
                current_config = new_config
            except Exception as ex:
                print(f'New settings failed: {ex}; trying previous config', file=sys.stderr)
                if current_config is not None:
                    try:
                        current_runner = await start_gateway(current_config)
                        print('Previous network configuration restored', flush=True)
                    except Exception as restore_ex:
                        print(f'FATAL: restore failed: {restore_ex}', file=sys.stderr)
                        raise
    finally:
        if current_runner:
            await current_runner.cleanup()
        _release_pid()


def ask(question: str, default: str) -> str:
    answer = input(f'{question} [{default}]: ').strip()
    return answer or default


def wizard() -> None:
    """Setup only uses human-entered addresses; secret never appears in console."""
    existing = load_existing_or_default()
    c = json.loads(json.dumps(existing))
    print('\nShade setup: enter the upstream websites (they are NOT created by Shade).')
    print('Each URL is an http://host:port or https://host:port origin.\n')
    c['backends']['public'] = ask('Public backend', c['backends']['public'])
    c['backends']['hidden'] = ask('Hidden backend', c['backends']['hidden'])
    g = c['gateway']
    g['bind_host'] = ask('Gateway bind IP (0.0.0.0 for public Internet with direct TLS)', g['bind_host'])
    g['bind_port'] = int(ask('Gateway listen port', str(g['bind_port'])))
    mode = ask('HTTPS [off/direct/reverse_proxy]', g['tls']['mode']).strip().lower()
    g['tls']['mode'] = mode
    if mode == 'direct':
        g['tls']['cert_file'] = ask('TLS certificate PEM path', g['tls']['cert_file'] or 'fullchain.pem')
        g['tls']['key_file'] = ask('TLS private key PEM path', g['tls']['key_file'] or 'privkey.pem')
    elif mode in ('off', 'reverse_proxy'):
        g['tls']['cert_file'] = ''
        g['tls']['key_file'] = ''
    g.pop('public_url', None)  # remove legacy setting when saving
    old_opaque = existing.get('auth', {}).get('scheme') == 'serenity-opaque-1.1.0'
    if not old_opaque or not existing['auth'].get('password_file'):
        print('\nOPAQUE credentials required. Registering a new password locally.')
        c = password_prompt(c)
    else:
        c['version'] = 2
        print('Existing OPAQUE credential record retained.')
    c = validate(c)
    save(c)
    print(f'\nSaved {CONFIG_PATH}. Run python server.py serve (or python server.py).')


def password_prompt(config: dict) -> dict:
    import opaque_adapter
    opaque_adapter.check()
    password = getpass('New Shade password (12+ characters): ')
    confirm = getpass('Repeat password: ')
    if password != confirm:
        raise ValueError('Passwords do not match')
    return change_password(config, password)


def notify_running() -> bool:
    pid = _owned_live_pid()
    if pid is None:
        return False
    os.kill(pid, signal.SIGHUP)
    print(f'Sent restart signal (SIGHUP) to Shade process {pid}. Sessions will be invalidated.')
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description='Shade Gateway — external backends and HTTPS')
    parser.add_argument('command', nargs='?', default='serve',
                        choices=['serve', 'init', 'configure', 'set-password', 'restart', 'stop', 'check'])
    args = parser.parse_args()
    try:
        if args.command in ('init', 'configure'):
            wizard()
        elif args.command == 'set-password':
            c = load_existing_or_default()
            c = password_prompt(c)
            save(c)
            print('Password updated. All existing sessions require a Gateway restart.')
            if not notify_running():
                print('Gateway is not running. Password will apply on next start.')
        elif args.command == 'check':
            c = load()
            build_tls_context(c)
            import opaque_adapter
            opaque_adapter.check()
            print(f'Configuration valid: {CONFIG_PATH}')
        elif args.command == 'restart':
            if not notify_running():
                raise ValueError('Gateway is not running. Use python server.py serve.')
        elif args.command == 'stop':
            pid = _owned_live_pid()
            if pid is None:
                raise ValueError('Gateway is not running')
            os.kill(pid, signal.SIGTERM)
            print(f'Sent stop signal to process {pid}')
        else:
            if sys.stdin.isatty():
                try:
                    load()
                except (FileNotFoundError, ValueError, KeyError, json.JSONDecodeError):
                    print('Shade has no valid server configuration. Starting first-run setup...')
                    wizard()
                else:
                    print(f'Config: {CONFIG_PATH}')
                    answer = input('Use saved addresses and ports? [Enter=yes / c=configure]: ').strip().lower()
                    if answer in ('c', 'configure'):
                        wizard()
            asyncio.run(serve())
    except KeyboardInterrupt:
        pass
    except (ValueError, KeyError, OSError, RuntimeError, json.JSONDecodeError, ssl.SSLError) as ex:
        parser.exit(1, f'Shade: {ex}\n')


if __name__ == '__main__':
    main()
