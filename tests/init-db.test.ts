import bcrypt from 'bcryptjs';
import { queryD1 } from '../src/utils/d1';
import { initDb } from '../src/scripts/init-db';

// The seed script against a stubbed D1: it must create the table, seed the admin from
// ADMIN_USERNAME / ADMIN_PASSWORD only when missing, never overwrite an existing admin (that would
// reset a changed password), and refuse to run without a strong password.
jest.mock('../src/utils/d1', () => ({ queryD1: jest.fn() }));
const mockedQuery = queryD1 as jest.MockedFunction<typeof queryD1>;

const sqlCalls = () => mockedQuery.mock.calls.map(([sql]) => sql.replace(/\s+/g, ' ').trim());

const PASSWORD = 'a-strong-test-password';

beforeEach(() => {
  process.env.ADMIN_USERNAME = 'admin';
  process.env.ADMIN_PASSWORD = PASSWORD;
  mockedQuery.mockReset();
  jest.spyOn(console, 'log').mockImplementation(() => {});
  jest.spyOn(console, 'error').mockImplementation(() => {});
});
afterEach(() => {
  delete process.env.ADMIN_USERNAME;
  delete process.env.ADMIN_PASSWORD;
  jest.restoreAllMocks();
});

it('creates the users table and seeds the admin with a bcrypt hash when absent', async () => {
  mockedQuery.mockResolvedValue([]);

  await initDb();

  const calls = sqlCalls();
  expect(calls[0]).toMatch(/^CREATE TABLE IF NOT EXISTS users/);
  const insert = mockedQuery.mock.calls.find(([sql]) => sql.startsWith('INSERT INTO users'));
  expect(insert).toBeDefined();
  const [username, hash, role] = insert![1] as string[];
  expect(username).toBe('admin');
  expect(role).toBe('admin');
  expect(hash).not.toBe(PASSWORD);
  expect(await bcrypt.compare(PASSWORD, hash)).toBe(true);
});

it('uses ADMIN_USERNAME when set', async () => {
  process.env.ADMIN_USERNAME = 'owner';
  mockedQuery.mockResolvedValue([]);

  await initDb();

  const insert = mockedQuery.mock.calls.find(([sql]) => sql.startsWith('INSERT INTO users'));
  expect((insert![1] as string[])[0]).toBe('owner');
});

it.each([
  ['unset', undefined],
  ['too short', 'short'],
  ['equal to the username', 'admin'],
])('refuses to seed when ADMIN_PASSWORD is %s', async (_label, password) => {
  if (password === undefined) delete process.env.ADMIN_PASSWORD;
  else process.env.ADMIN_PASSWORD = password;

  await initDb();

  expect(mockedQuery).not.toHaveBeenCalled();
  expect(console.error).toHaveBeenCalled();
});

it('refuses a password equal to a long username', async () => {
  process.env.ADMIN_USERNAME = 'administrator-account';
  process.env.ADMIN_PASSWORD = 'administrator-account';

  await initDb();

  expect(mockedQuery).not.toHaveBeenCalled();
});

it('leaves an existing admin untouched (idempotent)', async () => {
  mockedQuery.mockImplementation(
    async (sql) => (sql.startsWith('SELECT') ? [{ id: 1, username: 'admin' }] : []) as never,
  );

  await initDb();

  expect(sqlCalls().some((sql) => /^(INSERT|UPDATE|DELETE)/.test(sql))).toBe(false);
});

it('reports a D1 failure instead of crashing', async () => {
  mockedQuery.mockRejectedValue(new Error('D1 unreachable'));
  await expect(initDb()).resolves.toBeUndefined();
  expect(console.error).toHaveBeenCalled();
});
