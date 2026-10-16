import { queryD1, getUserByUsername, updatePassword } from '../src/utils/d1';

// The D1 REST API is stubbed at the fetch boundary (fake credentials come from setup-env.ts),
// so these check the requests we send and how responses/errors are handled.
const fetchMock = jest.spyOn(global, 'fetch');

const d1Ok = (results: unknown[]) =>
  new Response(JSON.stringify({ success: true, errors: [], result: [{ results }] }), {
    headers: { 'Content-Type': 'application/json' },
  });

const d1Error = (message: string) =>
  new Response(JSON.stringify({ success: false, errors: [{ message }], result: [] }), {
    status: 400,
    headers: { 'Content-Type': 'application/json' },
  });

const sentRequest = () => {
  const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
  return { url, init, body: JSON.parse(init.body as string) };
};

afterEach(() => fetchMock.mockReset());
afterAll(() => fetchMock.mockRestore());

describe('queryD1', () => {
  it('POSTs the SQL and params to the D1 query endpoint with the API token', async () => {
    fetchMock.mockResolvedValueOnce(d1Ok([{ id: 1 }]));

    const rows = await queryD1('SELECT * FROM users WHERE id = ?', [1]);

    expect(rows).toEqual([{ id: 1 }]);
    const { url, init, body } = sentRequest();
    expect(url).toBe(
      'https://api.cloudflare.com/client/v4/accounts/test-account/d1/database/test-database/query',
    );
    expect(init.method).toBe('POST');
    expect(init.headers).toMatchObject({
      Authorization: 'Bearer test-api-token',
      'Content-Type': 'application/json',
    });
    expect(body).toEqual({ sql: 'SELECT * FROM users WHERE id = ?', params: [1] });
  });

  it('sends an empty params array by default', async () => {
    fetchMock.mockResolvedValueOnce(d1Ok([]));
    await queryD1('SELECT 1');
    expect(sentRequest().body.params).toEqual([]);
  });

  it('throws the D1 error message when the query fails', async () => {
    fetchMock.mockResolvedValueOnce(d1Error('no such table: users'));
    await expect(queryD1('SELECT * FROM users')).rejects.toThrow('no such table: users');
  });

  it('throws a generic error when D1 fails without a message', async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ success: false, errors: [], result: [] })),
    );
    await expect(queryD1('SELECT 1')).rejects.toThrow('Database query failed');
  });

  it('propagates network failures', async () => {
    fetchMock.mockRejectedValueOnce(new TypeError('fetch failed'));
    await expect(queryD1('SELECT 1')).rejects.toThrow('fetch failed');
  });

  it('refuses to run without Cloudflare credentials', async () => {
    const saved = process.env.CLOUDFLARE_API_TOKEN;
    delete process.env.CLOUDFLARE_API_TOKEN;
    try {
      // d1.ts reads the env at load time, so load a fresh copy. dotenv must not refill the
      // token from a local .env, so stub it out for this load.
      let isolated!: typeof import('../src/utils/d1');
      jest.isolateModules(() => {
        jest.doMock('dotenv', () => ({ config: jest.fn() }));
        isolated = jest.requireActual('../src/utils/d1');
      });
      await expect(isolated.queryD1('SELECT 1')).rejects.toThrow(
        'Cloudflare credentials are not configured',
      );
      expect(fetchMock).not.toHaveBeenCalled();
    } finally {
      process.env.CLOUDFLARE_API_TOKEN = saved;
      jest.dontMock('dotenv');
    }
  });
});

describe('user queries', () => {
  it('getUserByUsername returns the matching user, using a bound parameter', async () => {
    const user = { id: 1, username: 'alice', password_hash: 'hash', role: 'admin' };
    fetchMock.mockResolvedValueOnce(d1Ok([user]));

    await expect(getUserByUsername("alice' OR '1'='1")).resolves.toEqual(user);
    const { body } = sentRequest();
    expect(body.sql).toBe('SELECT * FROM users WHERE username = ?');
    expect(body.params).toEqual(["alice' OR '1'='1"]);
  });

  it('getUserByUsername returns null when there is no such user', async () => {
    fetchMock.mockResolvedValueOnce(d1Ok([]));
    await expect(getUserByUsername('nobody')).resolves.toBeNull();
  });

  it('updatePassword updates only that user', async () => {
    fetchMock.mockResolvedValueOnce(d1Ok([]));
    await updatePassword('alice', 'new-hash');
    const { body } = sentRequest();
    expect(body.sql).toBe('UPDATE users SET password_hash = ? WHERE username = ?');
    expect(body.params).toEqual(['new-hash', 'alice']);
  });

  it('updatePassword surfaces D1 errors', async () => {
    fetchMock.mockResolvedValueOnce(d1Error('database is locked'));
    await expect(updatePassword('alice', 'new-hash')).rejects.toThrow('database is locked');
  });
});
