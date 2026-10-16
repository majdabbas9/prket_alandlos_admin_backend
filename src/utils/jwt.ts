import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

// No fallback: a known default would let anyone forge admin tokens, so refuse to start instead
const MIN_SECRET_LENGTH = 32;
const JWT_SECRET = process.env.JWT_SECRET ?? '';
if (JWT_SECRET.length < MIN_SECRET_LENGTH) {
  throw new Error(`JWT_SECRET must be set and at least ${MIN_SECRET_LENGTH} characters long`);
}

/**
 * Generate a JWT token
 * @param payload The data to be encrypted in the token
 * @param expiresIn Expiration time (e.g., '1h', '7d')
 * @returns The signed JWT token
 */
export const generateToken = (
  payload: object,
  expiresIn: jwt.SignOptions['expiresIn'] = '1h',
): string => {
  const options: jwt.SignOptions = { expiresIn, algorithm: 'HS256' };
  return jwt.sign(payload, JWT_SECRET, options);
};

/**
 * Validate a JWT token
 * @param token The JWT token to validate
 * @returns The decoded payload if valid, otherwise throws an error
 */
export const verifyToken = (token: string): object | string => {
  try {
    return jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
  } catch {
    throw new Error('Invalid or expired token');
  }
};
