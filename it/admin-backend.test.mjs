// Integration tests for the deployed admin backend (/auth/* on the API Worker).
// Read-only: login and token checks only - the password is never changed.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { request, waitUntilReady, login, hasCredentials, ADMIN_USERNAME } from './lib.mjs';

const needsCredentials = { skip: !hasCredentials && 'ADMIN_USERNAME / ADMIN_PASSWORD not set' };

before(async () => {
  // /auth/validate without a token answers 401 JSON once the container is up
  await waitUntilReady(
    'POST',
    '/auth/validate',
    (res) => res.status === 401 && res.body?.success === false,
    { body: {} },
  );
});

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
  assert.equal(viaHeader.body.data.username, ADMIN_USERNAME);

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
