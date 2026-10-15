// Shared helpers for the post-deploy integration tests (it/*.test.mjs). They run against the
// live API Worker, using only Node built-ins (node:test + fetch), so no npm install. Run by
// .github/workflows/integration-tests.yml after each publish run deploys to dev.
//   API_URL                          Worker URL (default: the dev workers.dev URL)
//   ADMIN_USERNAME / ADMIN_PASSWORD  admin credentials; tests that need a token skip without them

export const API_URL = (
  process.env.API_URL || 'https://prket-alandlos-api.majd-abbas222.workers.dev'
).replace(/\/+$/, '');
export const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
export const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
export const hasCredentials = Boolean(ADMIN_USERNAME && ADMIN_PASSWORD);

const REQUEST_TIMEOUT_MS = 30_000;

/** fetch against API_URL; returns { status, headers, body } with body parsed as JSON when it is JSON. */
export async function request(method, path, { body, token, headers = {} } = {}) {
  const init = { method, headers: { ...headers }, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) };
  if (token) init.headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  const res = await fetch(`${API_URL}${path}`, init);
  const isJson = (res.headers.get('content-type') || '').includes('application/json');
  return {
    status: res.status,
    headers: res.headers,
    body: isJson ? await res.json() : await res.arrayBuffer(),
  };
}

/**
 * Containers sleep after 15 min idle and a fresh deploy rolls them, so the first requests
 * can fail or hang while one cold-starts. Polls until `isReady(res)` holds.
 */
export async function waitUntilReady(method, path, isReady, { timeoutMs = 240_000, body } = {}) {
  const deadline = Date.now() + timeoutMs;
  let last = 'no response';
  while (Date.now() < deadline) {
    try {
      const res = await request(method, path, { body });
      if (res.status === 503 && res.body?.error === 'Service temporarily unavailable') {
        throw new Error(
          'API is switched off (Power workflow) - turn it on before running the tests',
        );
      }
      if (isReady(res)) return;
      last = `HTTP ${res.status}`;
    } catch (err) {
      if (err.message.startsWith('API is switched off')) throw err;
      last = err.message;
    }
    await new Promise((r) => setTimeout(r, 5_000));
  }
  throw new Error(`${method} ${path} not ready after ${timeoutMs / 1000}s (last: ${last})`);
}

/** Logs in as the admin and returns the JWT. */
export async function login() {
  const res = await request('POST', '/auth/login', {
    body: { username: ADMIN_USERNAME, password: ADMIN_PASSWORD },
  });
  if (res.status !== 200 || !res.body?.token) {
    throw new Error(`Admin login failed (HTTP ${res.status}): ${JSON.stringify(res.body)}`);
  }
  return res.body.token;
}
