import request from 'supertest';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import app from '../src/app';
import { getUserByUsername, updatePassword, User } from '../src/utils/d1';

// D1 is replaced by an in-memory users table, so the routes run their real bcrypt/JWT logic
// end to end and a password change is observable through later logins.
jest.mock('../src/utils/d1', () => ({
  getUserByUsername: jest.fn(),
  updatePassword: jest.fn(),
}));

const SECRET = process.env.JWT_SECRET as string;
const ADMIN = { username: 'admin', password: 'admin', role: 'admin' };

let users: Map<string, User>;
let adminHash: string;

const mockedGetUser = getUserByUsername as jest.MockedFunction<typeof getUserByUsername>;
const mockedUpdatePassword = updatePassword as jest.MockedFunction<typeof updatePassword>;

beforeAll(async () => {
  adminHash = await bcrypt.hash(ADMIN.password, 4);
});

beforeEach(() => {
  users = new Map([
    [
      ADMIN.username,
      { id: 1, username: ADMIN.username, password_hash: adminHash, role: ADMIN.role },
    ],
  ]);
  mockedGetUser.mockReset().mockImplementation(async (u) => users.get(u) ?? null);
  mockedUpdatePassword.mockReset().mockImplementation(async (u, hash) => {
    users.get(u)!.password_hash = hash;
  });
});

const login = (body: object) => request(app).post('/auth/login').send(body);

const loginToken = async () => {
  const res = await login({ username: ADMIN.username, password: ADMIN.password });
  expect(res.status).toBe(200);
  return res.body.token as string;
};

const expiredToken = () =>
  jwt.sign({ username: ADMIN.username, exp: Math.floor(Date.now() / 1000) - 60 }, SECRET);
const foreignToken = () => jwt.sign({ username: ADMIN.username, role: 'admin' }, 'other-secret');

describe('POST /auth/login', () => {
  it('returns a JWT with username and role (never the hash) for valid credentials', async () => {
    const res = await login({ username: ADMIN.username, password: ADMIN.password });

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ success: true, token: expect.any(String) });
    const decoded = jwt.verify(res.body.token, SECRET) as jwt.JwtPayload;
    expect(decoded).toMatchObject({ username: ADMIN.username, role: ADMIN.role });
    expect(decoded).not.toHaveProperty('password_hash');
    expect(decoded).not.toHaveProperty('password');
    expect(decoded.exp).toBeGreaterThan(Date.now() / 1000);
  });

  it('rejects a wrong password for an existing user with 401', async () => {
    const res = await login({ username: ADMIN.username, password: 'wrong' });
    expect(res.status).toBe(401);
    expect(res.body).toEqual({ success: false, message: 'Invalid credentials' });
  });

  it('rejects an unknown user with the same 401 (no user enumeration)', async () => {
    const res = await login({ username: 'nobody', password: ADMIN.password });
    expect(res.status).toBe(401);
    expect(res.body).toEqual({ success: false, message: 'Invalid credentials' });
  });

  it('is case-sensitive on the password', async () => {
    const res = await login({ username: ADMIN.username, password: ADMIN.password.toUpperCase() });
    expect(res.status).toBe(401);
  });

  it.each([
    ['an empty body', {}],
    ['a missing password', { username: 'admin' }],
    ['a missing username', { password: 'admin' }],
    ['empty strings', { username: '', password: '' }],
    ['a non-string password', { username: 'admin', password: 12345 }],
    ['an object username (injection attempt)', { username: { $ne: '' }, password: 'admin' }],
  ])('rejects %s with 400 without querying the database', async (_label, body) => {
    const res = await login(body);
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ success: false, message: 'Username and password are required' });
    expect(mockedGetUser).not.toHaveBeenCalled();
  });

  it('answers 500 without leaking details when the database fails', async () => {
    mockedGetUser.mockRejectedValueOnce(new Error('D1 is down: internal detail'));
    const res = await login({ username: ADMIN.username, password: ADMIN.password });
    expect(res.status).toBe(500);
    expect(res.body).toEqual({ success: false, message: 'Internal server error during login' });
  });
});

describe('POST /auth/validate', () => {
  it('accepts a login token from the Authorization header and returns its claims', async () => {
    const token = await loginToken();
    const res = await request(app).post('/auth/validate').set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ success: true, message: 'Token is valid' });
    expect(res.body.data).toMatchObject({ username: ADMIN.username, role: ADMIN.role });
    expect(typeof res.body.data.exp).toBe('number');
  });

  it('accepts the token in the JSON body', async () => {
    const token = await loginToken();
    const res = await request(app).post('/auth/validate').send({ token });
    expect(res.status).toBe(200);
    expect(res.body.data.username).toBe(ADMIN.username);
  });

  it('prefers the Authorization header over the body', async () => {
    const token = await loginToken();
    const res = await request(app)
      .post('/auth/validate')
      .set('Authorization', 'Bearer garbage')
      .send({ token });
    expect(res.status).toBe(401);
  });

  it.each([
    ['no header and no body', undefined, undefined],
    ['an empty Bearer header', 'Bearer ', undefined],
    ['a non-Bearer scheme', 'Basic YWRtaW46YWRtaW4=', undefined],
    ['an empty body token', undefined, { token: '' }],
  ])('returns 401 "Token is missing" for %s', async (_label, header, body) => {
    let req = request(app).post('/auth/validate');
    if (header) req = req.set('Authorization', header);
    const res = await (body ? req.send(body) : req);
    expect(res.status).toBe(401);
    expect(res.body).toEqual({ success: false, message: 'Token is missing' });
  });

  it.each([
    ['malformed', () => 'not-a-jwt'],
    ['expired', expiredToken],
    ['signed with another secret', foreignToken],
  ])('returns 401 for a %s token', async (_label, makeToken) => {
    const res = await request(app)
      .post('/auth/validate')
      .set('Authorization', `Bearer ${makeToken()}`);
    expect(res.status).toBe(401);
    expect(res.body).toEqual({ success: false, message: 'Invalid or expired token' });
  });
});

describe('POST /auth/change-password', () => {
  const changePassword = (token: string | undefined, body: object) => {
    const req = request(app).post('/auth/change-password');
    return (token ? req.set('Authorization', `Bearer ${token}`) : req).send(body);
  };

  it('changes the password: the new one logs in, the old one no longer does', async () => {
    const token = await loginToken();
    const res = await changePassword(token, {
      currentPassword: ADMIN.password,
      newPassword: 'n3w-pass',
    });

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ success: true, message: 'Password changed successfully' });
    expect(mockedUpdatePassword).toHaveBeenCalledTimes(1);
    const [username, storedHash] = mockedUpdatePassword.mock.calls[0];
    expect(username).toBe(ADMIN.username);
    expect(storedHash).not.toBe('n3w-pass'); // stored hashed, never in clear
    expect(await bcrypt.compare('n3w-pass', storedHash)).toBe(true);

    expect((await login({ username: ADMIN.username, password: 'n3w-pass' })).status).toBe(200);
    expect((await login({ username: ADMIN.username, password: ADMIN.password })).status).toBe(401);
  });

  it('accepts the token in the body', async () => {
    const token = await loginToken();
    const res = await changePassword(undefined, {
      token,
      currentPassword: ADMIN.password,
      newPassword: 'n3w-pass',
    });
    expect(res.status).toBe(200);
  });

  it('rejects a wrong current password with 401 and changes nothing', async () => {
    const token = await loginToken();
    const res = await changePassword(token, { currentPassword: 'wrong', newPassword: 'n3w-pass' });

    expect(res.status).toBe(401);
    expect(res.body).toEqual({ success: false, message: 'Incorrect current password' });
    expect(mockedUpdatePassword).not.toHaveBeenCalled();
    expect((await login({ username: ADMIN.username, password: ADMIN.password })).status).toBe(200);
  });

  it('returns 401 when the token is missing', async () => {
    const res = await changePassword(undefined, {
      currentPassword: ADMIN.password,
      newPassword: 'x',
    });
    expect(res.status).toBe(401);
    expect(res.body).toEqual({ success: false, message: 'Token is missing' });
    expect(mockedUpdatePassword).not.toHaveBeenCalled();
  });

  it.each([
    ['malformed', () => 'not-a-jwt'],
    ['expired', expiredToken],
    ['signed with another secret', foreignToken],
  ])('returns 401 for a %s token and changes nothing', async (_label, makeToken) => {
    const res = await changePassword(makeToken(), {
      currentPassword: ADMIN.password,
      newPassword: 'n3w-pass',
    });
    expect(res.status).toBe(401);
    expect(res.body.success).toBe(false);
    expect(mockedUpdatePassword).not.toHaveBeenCalled();
  });

  it.each([
    ['both passwords are missing', {}],
    ['newPassword is missing', { currentPassword: 'admin' }],
    ['currentPassword is missing', { newPassword: 'x' }],
    ['newPassword is empty', { currentPassword: 'admin', newPassword: '' }],
    ['newPassword is not a string', { currentPassword: 'admin', newPassword: 123456 }],
  ])('returns 400 when %s', async (_label, body) => {
    const token = await loginToken();
    const res = await changePassword(token, body);
    expect(res.status).toBe(400);
    expect(res.body).toEqual({
      success: false,
      message: 'Current password and new password are required',
    });
    expect(mockedUpdatePassword).not.toHaveBeenCalled();
  });

  it('returns 404 when the token is valid but the user no longer exists', async () => {
    const token = jwt.sign({ username: 'deleted-user', role: 'admin' }, SECRET);
    const res = await changePassword(token, { currentPassword: 'a', newPassword: 'b' });
    expect(res.status).toBe(404);
    expect(res.body).toEqual({ success: false, message: 'User not found' });
    expect(mockedUpdatePassword).not.toHaveBeenCalled();
  });
});
