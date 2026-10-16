import jwt from 'jsonwebtoken';
import { generateToken, verifyToken } from '../src/utils/jwt';

const SECRET = process.env.JWT_SECRET as string;

describe('jwt utils', () => {
  it('round-trips the payload and sets a 1h expiry by default', () => {
    const token = generateToken({ username: 'alice', role: 'admin' });
    const decoded = verifyToken(token) as jwt.JwtPayload;

    expect(decoded).toMatchObject({ username: 'alice', role: 'admin' });
    expect(typeof decoded.iat).toBe('number');
    expect(decoded.exp! - decoded.iat!).toBe(3600);
  });

  it('honours a custom expiry', () => {
    const decoded = verifyToken(generateToken({ username: 'alice' }, '7d')) as jwt.JwtPayload;
    expect(decoded.exp! - decoded.iat!).toBe(7 * 24 * 3600);
  });

  it('signs with the configured secret', () => {
    const token = generateToken({ username: 'alice' });
    expect(() => jwt.verify(token, SECRET)).not.toThrow();
    expect(() => jwt.verify(token, 'some-other-secret')).toThrow();
  });

  it('rejects an expired token', () => {
    const expired = jwt.sign(
      { username: 'alice', exp: Math.floor(Date.now() / 1000) - 60 },
      SECRET,
    );
    expect(() => verifyToken(expired)).toThrow('Invalid or expired token');
  });

  it('rejects a token signed with another secret', () => {
    const forged = jwt.sign({ username: 'alice', role: 'admin' }, 'attacker-secret');
    expect(() => verifyToken(forged)).toThrow('Invalid or expired token');
  });

  it('rejects a token whose payload was tampered with', () => {
    const [header, , signature] = generateToken({ username: 'alice', role: 'viewer' }).split('.');
    const payload = Buffer.from(JSON.stringify({ username: 'alice', role: 'admin' })).toString(
      'base64url',
    );
    expect(() => verifyToken(`${header}.${payload}.${signature}`)).toThrow(
      'Invalid or expired token',
    );
  });

  it('rejects an unsigned (alg "none") token', () => {
    const unsigned = jwt.sign({ username: 'alice', role: 'admin' }, '', { algorithm: 'none' });
    expect(() => verifyToken(unsigned)).toThrow('Invalid or expired token');
  });

  it.each(['', 'not-a-jwt', 'a.b.c'])('rejects malformed token %p', (token) => {
    expect(() => verifyToken(token)).toThrow('Invalid or expired token');
  });
});

describe('JWT_SECRET guard', () => {
  // dotenv is stubbed so .env can't fill in the secret being tested
  const loadWithSecret = async (secret: string | undefined) => {
    const original = process.env.JWT_SECRET;
    if (secret === undefined) delete process.env.JWT_SECRET;
    else process.env.JWT_SECRET = secret;
    try {
      await jest.isolateModulesAsync(async () => {
        jest.doMock('dotenv', () => ({ config: jest.fn() }));
        await import('../src/utils/jwt');
      });
    } finally {
      process.env.JWT_SECRET = original;
      jest.dontMock('dotenv');
    }
  };

  it.each([
    ['unset', undefined],
    ['empty', ''],
    ['too short', 'default_secret'],
  ])('refuses to load when JWT_SECRET is %s', async (_label, secret) => {
    await expect(loadWithSecret(secret)).rejects.toThrow(/JWT_SECRET must be set/);
  });

  it('loads with a long enough secret', async () => {
    await expect(loadWithSecret('x'.repeat(32))).resolves.toBeUndefined();
  });
});
