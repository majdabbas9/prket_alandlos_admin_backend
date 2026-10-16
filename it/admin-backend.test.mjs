// Integration tests for the deployed admin backend (/auth/* on the API Worker).
// Read-only: login and token checks only - the password is never changed (the success path is
// covered by the unit tests; changing the shared admin's real password risks a lockout).
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import {
  request,
  waitUntilReady,
  login,
  hasCredentials,
  API_URL,
  ADMIN_USERNAME,
  EXPECTED_VERSION,
} from './lib.mjs';

const needsCredentials = { skip: !hasCredentials && 'ADMIN_USERNAME / ADMIN_PASSWORD not set' };

before(async () => {
  // /auth/validate without a token answers 401 JSON once the container is up
  await waitUntilReady(
    'POST',
    '/auth/validate',
    (res) => res.status === 401 && res.body?.success === false,
    { body: {} },
  );
  // Right after a deploy the old container can keep serving for a while; wait for this commit
  if (EXPECTED_VERSION) {
    await waitUntilReady('GET', '/health', (res) => res.body?.version === EXPECTED_VERSION);
  }
});

test('health check answers', async () => {
  const res = await request('GET', '/health');
  assert.equal(res.status, 200);
  assert.equal(typeof res.body.status, 'string');
});

// With a custom domain CORS only allows the admin site (CI sets CORS_ORIGINS), whose hostname is
// the auth one with "auth" -> "admin" (auth.example.com -> admin.example.com, dev-auth.* ->
// dev-admin.*). On workers.dev CORS stays open.
const apiHost = new URL(API_URL).hostname;
const customDomain = !apiHost.endsWith('.workers.dev');
const ADMIN_ORIGIN = customDomain
  ? `https://${apiHost.replace(/^((?:.*-)?)auth\./, '$1admin.')}`
  : 'https://admin.example.com';

const preflight = (origin) =>
  request('OPTIONS', '/auth/login', {
    headers: {
      Origin: origin,
      'Access-Control-Request-Method': 'POST',
      'Access-Control-Request-Headers': 'content-type,authorization',
    },
  });

test('CORS preflight allows the admin frontend to POST with a bearer token', async () => {
  const res = await preflight(ADMIN_ORIGIN);
  assert.ok(res.status === 200 || res.status === 204, `HTTP ${res.status}`);
  const allowed = res.headers.get('access-control-allow-origin');
  assert.ok(allowed === ADMIN_ORIGIN || allowed === '*', `Access-Control-Allow-Origin: ${allowed}`);
});

test(
  'CORS does not allow other websites',
  { skip: !customDomain && 'CORS is open on workers.dev' },
  async () => {
    const res = await preflight('https://evil.example');
    assert.equal(res.headers.get('access-control-allow-origin'), null);
  },
);

test('validate rejects a request with no token', async () => {
  const res = await request('POST', '/auth/validate', { body: {} });
  assert.equal(res.status, 401);
  assert.equal(res.body.success, false);
  assert.equal(res.body.message, 'Token is missing');
});

test('validate rejects a malformed token', async () => {
  const res = await request('POST', '/auth/validate', { token: 'not-a-jwt' });
  assert.equal(res.status, 401);
  assert.equal(res.body.success, false);
});

test('validate rejects a token signed with another secret', async () => {
  // header {"alg":"HS256","typ":"JWT"}, payload {"username":"x"}, bogus signature
  const forged = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IngifQ.c2lnbmF0dXJl';
  const res = await request('POST', '/auth/validate', { token: forged });
  assert.equal(res.status, 401);
  assert.equal(res.body.success, false);
});

test('login rejects an unknown user', async () => {
  const res = await request('POST', '/auth/login', {
    body: { username: `it-nobody-${Date.now()}`, password: 'wrong' },
  });
  assert.equal(res.status, 401);
  assert.equal(res.body.success, false);
  assert.equal(res.body.message, 'Invalid credentials');
});

test('login rejects missing credentials with 400', async () => {
  for (const body of [{}, { username: 'admin' }, { password: 'x' }]) {
    const res = await request('POST', '/auth/login', { body });
    assert.equal(res.status, 400, `body ${JSON.stringify(body)}`);
    assert.equal(res.body.success, false);
  }
});

test('login rejects a malformed JSON body with 400', async () => {
  const res = await fetch(`${API_URL}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '{"username": "admin", "password":',
    signal: AbortSignal.timeout(30_000),
  });
  assert.equal(res.status, 400);
});

test('login rejects a wrong password', needsCredentials, async () => {
  const res = await request('POST', '/auth/login', {
    body: { username: ADMIN_USERNAME, password: `wrong-${Date.now()}` },
  });
  assert.equal(res.status, 401);
  assert.equal(res.body.success, false);
});

test('login returns a token that validates', needsCredentials, async () => {
  const token = await login();
  assert.equal(token.split('.').length, 3, 'token should be a JWT');

  const viaHeader = await request('POST', '/auth/validate', { token });
  assert.equal(viaHeader.status, 200);
  assert.equal(viaHeader.body.success, true);
  const claims = viaHeader.body.data;
  assert.equal(claims.username, ADMIN_USERNAME);
  assert.equal(typeof claims.role, 'string');
  assert.ok(claims.exp > Date.now() / 1000, 'token should not be expired');
  assert.equal(claims.password_hash, undefined, 'token must not carry the password hash');

  const viaBody = await request('POST', '/auth/validate', { body: { token } });
  assert.equal(viaBody.status, 200);
  assert.equal(viaBody.body.data.username, ADMIN_USERNAME);
});

test('change-password requires a token', async () => {
  const res = await request('POST', '/auth/change-password', {
    body: { currentPassword: 'a', newPassword: 'b' },
  });
  assert.equal(res.status, 401);
  assert.equal(res.body.message, 'Token is missing');
});

test('change-password rejects an invalid token', async () => {
  const res = await request('POST', '/auth/change-password', {
    token: 'not-a-jwt',
    body: { currentPassword: 'a', newPassword: 'b' },
  });
  assert.equal(res.status, 401);
  assert.equal(res.body.success, false);
});

test('change-password requires both passwords', needsCredentials, async () => {
  const token = await login();
  const res = await request('POST', '/auth/change-password', { token, body: { newPassword: 'x' } });
  assert.equal(res.status, 400);
  assert.equal(res.body.success, false);
});

test(
  'change-password rejects a wrong current password without changing it',
  needsCredentials,
  async () => {
    const token = await login();
    const res = await request('POST', '/auth/change-password', {
      token,
      body: { currentPassword: `wrong-${Date.now()}`, newPassword: 'never-applied' },
    });
    assert.equal(res.status, 401);
    assert.equal(res.body.message, 'Incorrect current password');
    // The real password must still work
    await login();
  },
);
