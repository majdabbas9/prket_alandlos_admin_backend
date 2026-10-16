import request from 'supertest';
import app from '../src/app';

// App-level behaviour: health check, CORS for the admin frontend, body parsing and fallbacks.
// None of these paths reach D1.
describe('app', () => {
  it('GET /health reports the server is up', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/application\/json/);
    expect(res.body).toEqual({
      status: 'Auth server is running',
      version: process.env.GIT_SHA || 'unknown',
    });
  });

  it('answers CORS preflight for cross-origin login requests', async () => {
    const res = await request(app)
      .options('/auth/login')
      .set('Origin', 'https://admin.example.com')
      .set('Access-Control-Request-Method', 'POST')
      .set('Access-Control-Request-Headers', 'content-type,authorization');
    expect(res.status).toBe(204);
    expect(res.headers['access-control-allow-origin']).toBe('*');
    expect(res.headers['access-control-allow-methods']).toMatch(/POST/);
  });

  it('adds the CORS header to normal responses', async () => {
    const res = await request(app).get('/health').set('Origin', 'https://admin.example.com');
    expect(res.headers['access-control-allow-origin']).toBe('*');
  });

  it('only allows the configured origins when CORS_ORIGINS is set', async () => {
    process.env.CORS_ORIGINS = 'https://admin.example.com/, https://other.example.com';
    try {
      let restricted: typeof app = app;
      jest.isolateModules(() => {
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        restricted = require('../src/app').default;
      });
      const allowed = await request(restricted)
        .get('/health')
        .set('Origin', 'https://admin.example.com');
      expect(allowed.headers['access-control-allow-origin']).toBe('https://admin.example.com');
      const other = await request(restricted).get('/health').set('Origin', 'https://evil.example');
      expect(other.headers['access-control-allow-origin']).toBeUndefined();
    } finally {
      delete process.env.CORS_ORIGINS;
    }
  });

  it('rejects a malformed JSON body with 400, not 500', async () => {
    const res = await request(app)
      .post('/auth/login')
      .set('Content-Type', 'application/json')
      .send('{"username": "admin", "password":');
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error');
  });

  it('returns 404 for unknown routes', async () => {
    expect((await request(app).get('/nope')).status).toBe(404);
    expect((await request(app).get('/auth/login')).status).toBe(404); // login is POST only
  });
});
