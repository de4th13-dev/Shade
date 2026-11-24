// Local self-test; no configuration or user password is read or written.
import {randomBytes} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import assert from 'node:assert/strict';
import {ready, client} from '@serenity-kit/opaque';
await ready;
const worker = fileURLToPath(new URL('../server/opaque_bridge.mjs', import.meta.url));
function call(op, fields = {}, reject = false) {
  const p = spawnSync(process.execPath, [worker], {input: JSON.stringify({op, ...fields}), encoding:'utf8', timeout:20000});
  if (p.error) throw p.error;
  if (reject) { assert.equal(p.status, 1, 'Invalid KE3 must be rejected'); return; }
  assert.equal(p.status, 0, `OPAQUE worker failed: ${op}`);
  return JSON.parse(p.stdout);
}
const password = randomBytes(32).toString('hex');
const {setup, record} = call('register', {password});
const initial = client.startLogin({password});
const challenge = call('start', {setup,record,ke1:initial.startLoginRequest});
const finish = client.finishLogin({password,clientLoginState:initial.clientLoginState,loginResponse:challenge.ke2});
assert.ok(finish?.finishLoginRequest);
assert.equal(call('finish',{ke3:finish.finishLoginRequest,state:challenge.state}).verified,true);
call('finish',{ke3:'invalid',state:challenge.state},true);
const wrong = password + '-wrong';
const bad = client.startLogin({password:wrong});
const response = call('start',{setup,record,ke1:bad.startLoginRequest});
let failure;
try { failure = client.finishLogin({password:wrong,clientLoginState:bad.clientLoginState,loginResponse:response.ke2}); } catch { failure = null; }
assert.ok(!failure?.finishLoginRequest, 'Wrong password must not authenticate');
console.log('OPAQUE: регистрация, вход и отказ при неверном пароле — OK');
