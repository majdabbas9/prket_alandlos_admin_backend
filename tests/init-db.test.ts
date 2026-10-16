import bcrypt from 'bcryptjs';
import { queryD1 } from '../src/utils/d1';
import { initDb } from '../src/scripts/init-db';

// The seed script against a stubbed D1: it must create the table, seed admin/admin only when
// missing, and never overwrite an existing admin (that would reset a changed password).
jest.mock('../src/utils/d1', () => ({ queryD1: jest.fn() }));
const mockedQuery = queryD1 as jest.MockedFunction<typeof queryD1>;

const sqlCalls = () => mockedQuery.mock.calls.map(([sql]) => sql.replace(/\s+/g, ' ').trim());

beforeEach(() => {
  mockedQuery.mockReset();
  jest.spyOn(console, 'log').mockImplementation(() => {});
  jest.spyOn(console, 'error').mockImplementation(() => {});
});
afterEach(() => jest.restoreAllMocks());

it('creates the users table and seeds admin/admin with a bcrypt hash when absent', async () => {
  mockedQuery.mockResolvedValue([]);

  await initDb();

  const calls = sqlCalls();
  expect(calls[0]).toMatch(/^CREATE TABLE IF NOT EXISTS users/);
  const insert = mockedQuery.mock.calls.find(([sql]) => sql.startsWith('INSERT INTO users'));
  expect(insert).toBeDefined();
  const [username, hash, role] = insert![1] as string[];
  expect(username).toBe('admin');
  expect(role).toBe('admin');
  expect(hash).not.toBe('admin');
  expect(await bcrypt.compare('admin', hash)).toBe(true);
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
