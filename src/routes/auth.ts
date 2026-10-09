import { Router, Request, Response } from 'express';
import { generateToken, verifyToken } from '../utils/jwt';
import { getUserByUsername, updatePassword } from '../utils/d1';
import bcrypt from 'bcryptjs';
import { getLogger } from '../utils/logger';

const router = Router();
const logger = getLogger(__filename);

// Login route using D1
router.post('/login', async (req: Request, res: Response) => {
  const { username, password } = req.body;

  try {
    const user = await getUserByUsername(username);

    if (user && (await bcrypt.compare(password, user.password_hash))) {
      const payload = {
        username: user.username,
        role: user.role,
      };

      const token = generateToken(payload);

      res.json({
        success: true,
        token,
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

// Validate JWT token route
router.post('/validate', (req: Request, res: Response) => {
  // Try to get token from Authorization header or body
  const authHeader = req.headers.authorization;
  const tokenFromBody = req.body?.token;

  let token = '';

  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.split(' ')[1];
  } else if (tokenFromBody) {
    token = tokenFromBody;
  }

  if (!token) {
    res.status(401).json({
      success: false,
      message: 'Token is missing',
    });
    return;
  }

  try {
    const decoded = verifyToken(token);
    res.json({
      success: true,
      message: 'Token is valid',
      data: decoded,
    });
  } catch (error) {
    logger.error({ err: error }, 'Token validation error');
    res.status(401).json({
      success: false,
      message: error instanceof Error ? error.message : 'Invalid token',
    });
  }
});

// Change password route
router.post('/change-password', async (req: Request, res: Response) => {
  const authHeader = req.headers.authorization;
  const tokenFromBody = req.body?.token;
  const { currentPassword, newPassword } = req.body;

  let token = '';
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.split(' ')[1];
  } else if (tokenFromBody) {
    token = tokenFromBody;
  }

  if (!token) {
    res.status(401).json({
      success: false,
      message: 'Token is missing',
    });
    return;
  }

  if (!currentPassword || !newPassword) {
    res.status(400).json({
      success: false,
      message: 'Current password and new password are required',
    });
    return;
  }

  try {
    const decoded = verifyToken(token) as { username: string };
    const username = decoded.username;

    const user = await getUserByUsername(username);
    if (!user) {
      res.status(404).json({
        success: false,
        message: 'User not found',
      });
      return;
    }

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

    await updatePassword(username, newHash);

    res.json({
      success: true,
      message: 'Password changed successfully',
    });
  } catch (error) {
    logger.error({ err: error }, 'Change password error');
    res.status(401).json({
      success: false,
      message: error instanceof Error ? error.message : 'Invalid or expired token',
    });
  }
});

export default router;
