import sys
import unittest
from copy import deepcopy
from pathlib import Path
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'server'))
from configuration import DEFAULT, validate
from protocol import request_origin
from server import create_gateway_app
from test_form_origin import FakeOpaque

class ConfigurationTest(unittest.TestCase):
    def test_legacy_config(self):
        config = deepcopy(DEFAULT)
        config['gateway']['public_url'] = 'ignored-old-value'
        self.assertNotIn('public_url', validate(config, require_key=False)['gateway'])
        config['gateway']['tls']['mode'] = 'reverse_proxy'
        self.assertNotIn('public_url', validate(config, require_key=False)['gateway'])
        config['gateway']['bind_host'] = '0.0.0.0'
        with self.assertRaises(ValueError):
            validate(config, require_key=False)

    def test_host_validation(self):
        for host in ['a.example/path', 'a.example@b.example', 'a.example:0', 'a.example:', 'a.example,b.example', 'a.example\\bad', 'a.example:99999', 'a.example%2f']:
            with self.assertRaises(ValueError, msg=host):
                request_origin('https', host)
        self.assertEqual(request_origin('https', 'EXAMPLE.com:443'), 'https://example.com')
        self.assertEqual(request_origin('https', '[::1]:8443'), 'https://[::1]:8443')

class DynamicOriginTest(unittest.IsolatedAsyncioTestCase):
    async def test_aliases_and_csrf(self):
        async def public(r): return web.Response(text='public')
        async def hidden(r):
            if r.path == '/redirect':
                return web.Response(status=303, headers={'Location': f'http://{r.host}/admin/'})
            return web.Response(text='hidden')
        a, b = web.Application(), web.Application()
        a.router.add_route('*', '/{path:.*}', public)
        b.router.add_route('*', '/{path:.*}', hidden)
        async with TestServer(a) as pa, TestServer(b) as pb:
            app = create_gateway_app({'server_setup':'a','password_file':'b','credential_id':'c'}, str(pa.make_url('/')), str(pb.make_url('/')), tls_mode='reverse_proxy', opaque_lib=FakeOpaque)
            async with TestClient(TestServer(app)) as c:
                async def login(host):
                    h = {'Host':host}
                    r = await c.post('/.well-known/shade-opaque/start', json={'ke1':'x'}, headers=h)
                    attempt = (await r.json())['attempt']
                    r = await c.post('/.well-known/shade-opaque/finish', json={'attempt':attempt,'ke3':'valid'}, headers=h)
                    return (await r.json())['session_token']
                for host in ('one.example:443', 'two.example:8443'):
                    token = await login(host)
                    h = {'Host':host,'Cookie':'__Host-Shade-Session='+token}
                    origin = request_origin('https',host)
                    r = await c.post('/admin/login', headers=h|{'Origin':origin,'Sec-Fetch-Site':'same-origin','X-Forwarded-Proto':'http'})
                    self.assertEqual(await r.text(), 'hidden')
                    r = await c.post('/admin/login', headers=h|{'Origin':'https://evil.example'})
                    self.assertEqual(r.status,403)
                    r = await c.get('/redirect', headers=h, allow_redirects=False)
                    self.assertEqual(r.headers['Location'],origin+'/admin/')
                    r = await c.get('/', headers=h|{'Host':'third.example'})
                    self.assertEqual(await r.text(),'public')
                r = await c.post('/.well-known/shade-opaque/start', json={'ke1':'x'}, headers={'Host':'one.example'})
                attempt = (await r.json())['attempt']
                r = await c.post('/.well-known/shade-opaque/finish', json={'attempt':attempt,'ke3':'valid'}, headers={'Host':'two.example'})
                self.assertEqual(await r.text(),'public')
