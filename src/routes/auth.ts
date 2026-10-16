import { Router, Request, Response } from 'express';
import crypto from 'crypto';
import { generateToken, verifyToken } from '../utils/jwt';
import { getUserByUsername, updatePassword, User } from '../utils/d1';
import bcrypt from 'bcryptjs';
import { getLogger } from '../utils/logger';
import { loginRetryAfter, recordLoginAttempt, recordLoginSuccess } from '../utils/loginLimiter';

const router = Router();
const logger = getLogger(__filename);

const MIN_PASSWORD_LENGTH = 12;

// bcrypt hash (cost 10, like real ones) of a random string nobody knows. An unknown username is
// compared against it, so it costs the same bcrypt work as a wrong password and response times
// don't reveal which usernames exist.
const DUMMY_HASH = '$2b$10$Wut37qNfrtDn2yGhbl6zBOtkXSXRJoqpilJS.p/CIC0Bf4hOc1QX.';

/**
 * Short fingerprint of the user's current password hash, stored in their tokens. Changing the
 * password changes it, so every token issued before the change stops validating.
 */
const passwordVersion = (passwordHash: string) =>
  crypto.createHash('sha256').update(passwordHash).digest('base64url').slice(0, 16);

const issueToken = (user: User) =>
  generateToken({
    username: user.username,
    role: user.role,
    pwv: passwordVersion(user.password_hash),
  });

class InvalidTokenError extends Error {
  constructor() {
    super('Invalid or expired token');
  }
}

// Authorization: Bearer header first, then a "token" field in the JSON body
const tokenFrom = (req: Request): string => {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) return authHeader.split(' ')[1];
  const tokenFromBody = req.body?.token;
  return typeof tokenFromBody === 'string' ? tokenFromBody : '';
};

/**
 * Verifies the token and that it was issued for the user's current password (so it wasn't
 * revoked by a password change, and the user still exists). Throws InvalidTokenError if not;
 * any other error is a database failure.
 */
const authenticate = async (token: string) => {
  let decoded: { username?: unknown; pwv?: unknown };
  try {
    decoded = verifyToken(token) as typeof decoded;
  } catch {
    throw new InvalidTokenError();
  }
  if (typeof decoded.username !== 'string' || typeof decoded.pwv !== 'string') {
    throw new InvalidTokenError();
  }
  const user = await getUserByUsername(decoded.username);
  if (!user || passwordVersion(user.password_hash) !== decoded.pwv) {
    throw new InvalidTokenError();
  }
  return { decoded, user };
};

const sendTokenError = (res: Response, error: unknown, context: string) => {
  if (error instanceof InvalidTokenError) {
    res.status(401).json({ success: false, message: error.message });
    return;
  }
  logger.error({ err: error }, `${context} error`);
  res.status(500).json({ success: false, message: 'Internal server error' });
};

// Login route using D1
router.post('/login', async (req: Request, res: Response) => {
  const { username, password } = req.body ?? {};

  if (typeof username !== 'string' || typeof password !== 'string' || !username || !password) {
    res.status(400).json({
      success: false,
      message: 'Username and password are required',
    });
    return;
  }

  // On Cloudflare the Worker forwards the request, so the client's address is in CF-Connecting-IP
  const clientIp = req.get('cf-connecting-ip') ?? req.ip ?? 'unknown';
  const retryAfter = loginRetryAfter(clientIp, username);
  if (retryAfter > 0) {
    logger.warn({ clientIp, username }, 'Login rate limit hit');
    res.set('Retry-After', String(retryAfter));
    res.status(429).json({
      success: false,
      message: 'Too many failed login attempts, try again later',
    });
    return;
  }
  recordLoginAttempt(clientIp, username);

  try {
    const user = await getUserByUsername(username);
    const passwordMatches = await bcrypt.compare(password, user?.password_hash ?? DUMMY_HASH);

    if (user && passwordMatches) {
      recordLoginSuccess(clientIp, username);
      res.json({
        success: true,
        token: issueToken(user),
      });
    } else {
      res.status(401).json({
        success: false,
        message: 'Invalid credentials',
      });
    }
  } catch (error) {
    logger.error({ err: error }, 'Login error');
    res.status(500).json({
      success: false,
      message: 'Internal server error during login',
    });
  }
});

// Validate JWT token route (the main backend calls this for every admin write)
router.post('/validate', async (req: Request, res: Response) => {
  const token = tokenFrom(req);
  if (!token) {
    res.status(401).json({
      success: false,
      message: 'Token is missing',
    });
    return;
  }

  try {
    const { decoded, user } = await authenticate(token);
    res.json({
      success: true,
      message: 'Token is valid',
      // The role comes from the database, so a role change applies to existing tokens at once
      data: { ...decoded, role: user.role },
    });
  } catch (error) {
    sendTokenError(res, error, 'Token validation');
  }
});

// Change password route
router.post('/change-password', async (req: Request, res: Response) => {
  const token = tokenFrom(req);
  const { currentPassword, newPassword } = req.body ?? {};

  if (!token) {
    res.status(401).json({
      success: false,
      message: 'Token is missing',
    });
    return;
  }

  if (
    typeof currentPassword !== 'string' ||
    typeof newPassword !== 'string' ||
    !currentPassword ||
    !newPassword
  ) {
    res.status(400).json({
      success: false,
      message: 'Current password and new password are required',
    });
    return;
  }

  if (newPassword.length < MIN_PASSWORD_LENGTH || newPassword === currentPassword) {
    res.status(400).json({
      success: false,
      message: `New password must be at least ${MIN_PASSWORD_LENGTH} characters and differ from the current one`,
    });
    return;
  }

  try {
    const { user } = await authenticate(token);

    const isMatch = await bcrypt.compare(currentPassword, user.password_hash);
    if (!isMatch) {
      res.status(401).json({
        success: false,
        message: 'Incorrect current password',
      });
      return;
    }

    const salt = await bcrypt.genSalt(10);
    const newHash = await bcrypt.hash(newPassword, salt);

    await updatePassword(user.username, newHash);

    // Tokens issued before the change no longer validate, so hand back a fresh one
    res.json({
      success: true,
      message: 'Password changed successfully',
      token: issueToken({ ...user, password_hash: newHash }),
    });
  } catch (error) {
    sendTokenError(res, error, 'Change password');
  }
});

export default router;
