// Local crypto worker. No sockets, no shell, no secrets in argv or stderr.
import * as opaque from '@serenity-kit/opaque';
await opaque.ready;
const identity = 'shade-default';
function nonempty(value) {
  if (typeof value !== 'string' || !value.length || value.length > 8192)
    throw new Error('Invalid OPAQUE value');
  return value;
}
let input = '';
for await (const chunk of process.stdin) {
  input += chunk;
  if (input.length > 65536) throw new Error('Input limit');
}
try {
  const a = JSON.parse(input);
  let result;
  switch (a.op) {
    case 'check':
      if (typeof opaque.server.finishLogin !== 'function' || typeof opaque.client.finishRegistration !== 'function') throw new Error('Unsupported library API');
      result = {ready: true}; break;
    case 'register': {
      const password = nonempty(a.password);
      const serverSetup = nonempty(opaque.server.createSetup());
      const {clientRegistrationState, registrationRequest} = opaque.client.startRegistration({password});
      const {registrationResponse} = opaque.server.createRegistrationResponse({serverSetup, userIdentifier: identity, registrationRequest});
      const {registrationRecord} = opaque.client.finishRegistration({clientRegistrationState, registrationResponse, password});
      result = {setup: serverSetup, record: nonempty(registrationRecord)}; break;
    }
    case 'start': {
      const {loginResponse, serverLoginState} = opaque.server.startLogin({
        serverSetup: nonempty(a.setup), registrationRecord: nonempty(a.record),
        userIdentifier: identity, startLoginRequest: nonempty(a.ke1)
      });
      result = {ke2: nonempty(loginResponse), state: nonempty(serverLoginState)}; break;
    }
    case 'finish': {
      const verified = opaque.server.finishLogin({finishLoginRequest: nonempty(a.ke3), serverLoginState: nonempty(a.state)});
      nonempty(verified?.sessionKey); // throws on rejection or unexpected return
      result = {verified: true}; break;
    }
    default: throw new Error('Unknown operation');
  }
  process.stdout.write(JSON.stringify(result));
} catch (_) {
  // Generic failure; never print the input, password, key or library stack.
  process.exitCode = 1;
}
