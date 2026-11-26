"""Regression tests for ordinary HTML forms with Referrer-Policy: no-referrer."""
import asyncio
import sys
import unittest
from pathlib import Path
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'server'))
from server import create_gateway_app

class FakeOpaque:
    @staticmethod
    def login(*args): return 'ke2', 'state'
    @staticmethod
    def login_finish(message, state): return message == 'valid' and state == 'state'

class FormOriginTest(unittest.IsolatedAsyncioTestCase):
    async def test_routing(self):
        calls = []
        async def public(r):
            calls.append(('public', r.method, r.path, await r.read()))
            return web.Response(status=404 if r.path != '/' else 200, text='public')
        async def hidden(r):
            calls.append(('hidden', r.method, r.path, await r.read()))
            return web.Response(status=303, headers={'Location':'/admin/'})
        a,b=web.Application(),web.Application()
        a.router.add_route('*','/{path:.*}',public);b.router.add_route('*','/{path:.*}',hidden)
        async with TestServer(a) as pa, TestServer(b) as pb:
            app=create_gateway_app({'server_setup':'a','password_file':'b','credential_id':'c'},str(pa.make_url('/')),str(pb.make_url('/')),opaque_lib=FakeOpaque)
            async with TestClient(TestServer(app)) as c:
                r=await c.post('/.well-known/shade-opaque/start',json={'ke1':'x'});attempt=(await r.json())['attempt']
                r=await c.post('/.well-known/shade-opaque/finish',json={'attempt':attempt,'ke3':'valid'});token=(await r.json())['session_token']
                cookie={'Cookie':'shade_session='+token}
                metadata={'Sec-Fetch-Site':'same-origin','Sec-Fetch-Mode':'navigate','Sec-Fetch-Dest':'document'}
                for origin in ['null', str(c.make_url('/')).rstrip('/')]:
                    r=await c.post('/admin/login',data=b'form',headers=cookie|metadata|{'Origin':origin},allow_redirects=False)
                    self.assertEqual(r.status,303);self.assertEqual(r.headers['Location'],'/admin/');self.assertEqual(calls[-1],('hidden','POST','/admin/login',b'form'))
                before=len(calls)
                for h in [{'Origin':'null'}, metadata|{'Origin':'null','Sec-Fetch-Site':'cross-site'}, metadata|{'Origin':'null','Sec-Fetch-Site':'same-site'},metadata|{'Origin':'null','Sec-Fetch-Mode':'cors'},metadata|{'Origin':'null','Sec-Fetch-Dest':'iframe'},metadata|{'Origin':'https://other.test'}]:
                    r=await c.post('/admin/login',data=b'form',headers=cookie|h,allow_redirects=False)
                    self.assertEqual(r.status,403)
                self.assertEqual(len(calls),before)
                r=await c.post('/.well-known/shade-opaque/finish',json={'attempt':'bad','ke3':'bad'});self.assertEqual(r.status,200);self.assertEqual(calls[-1],('public','GET','/',b''))

if __name__=='__main__': unittest.main()
