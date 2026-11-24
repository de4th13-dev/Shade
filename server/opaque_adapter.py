"""Local JSON/stdin adapter for a pinned OPAQUE library, no network listener."""
import json
from pathlib import Path
import shutil
import subprocess
import threading

WORKER = Path(__file__).with_name('opaque_bridge.mjs')
SCHEME = 'serenity-opaque-1.1.0'
_slots = threading.BoundedSemaphore(4)


def _call(op, **args):
    node = shutil.which('node')
    if node is None:
        raise RuntimeError('Node.js is required; install Node.js 22+ and npm')
    if not (WORKER.parent.parent / 'node_modules' / '@serenity-kit' / 'opaque' / 'package.json').is_file():
        raise RuntimeError('OPAQUE library missing; run npm install in the Shade project root')
    if not _slots.acquire(blocking=False):
        raise RuntimeError('OPAQUE worker busy')
    try:
        process = subprocess.run(
            [node, str(WORKER)], input=json.dumps({'op': op, **args}),
            capture_output=True, text=True, timeout=20, check=False,
        )
        if process.returncode != 0:
            raise RuntimeError('OPAQUE operation failed; verify the npm dependency and credentials')
        try:
            result = json.loads(process.stdout)
        except (ValueError, TypeError) as ex:
            raise RuntimeError('Invalid response from OPAQUE worker') from ex
        if not isinstance(result, dict):
            raise RuntimeError('Invalid response from OPAQUE worker')
        return result
    except subprocess.TimeoutExpired as ex:
        raise RuntimeError('OPAQUE operation timed out') from ex
    finally:
        _slots.release()


def _string(obj, field):
    value = obj.get(field)
    if not isinstance(value, str) or not 0 < len(value) <= 8192:
        raise RuntimeError('Invalid OPAQUE worker output')
    return value


def check():
    if _call('check').get('ready') is not True:
        raise RuntimeError('OPAQUE library did not initialize')


def register(password):
    result = _call('register', password=password)
    return _string(result, 'setup'), _string(result, 'record')


def login(setup, record, ke1, identity):
    if identity != 'shade-default':
        raise ValueError('Invalid identity')
    result = _call('start', setup=setup, record=record, ke1=ke1)
    return _string(result, 'ke2'), _string(result, 'state')


def login_finish(ke3, state):
    if _call('finish', ke3=ke3, state=state).get('verified') is not True:
        raise RuntimeError('OPAQUE verification failed')
    return True
