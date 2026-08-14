import { Router, Request, Response } from 'express';
import { generateToken, verifyToken } from '../utils/jwt';
import { getUserByUsername } from '../utils/d1';
import bcrypt from 'bcryptjs';

const router = Router();

// Login route using D1
router.post('/login', async (req: Request, res: Response) => {
  const { username, password } = req.body;

  try {
    const user = await getUserByUsername(username);

    if (user && await bcrypt.compare(password, user.password_hash)) {
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
  } catch (error: any) {
    console.error("LOGIN ERROR", error);
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
  } catch (error: any) {
    console.error("VALIDATE ERROR", error);
    res.status(401).json({
      success: false,
      message: error.message || 'Invalid token',
    });
  }
});

export default router;
