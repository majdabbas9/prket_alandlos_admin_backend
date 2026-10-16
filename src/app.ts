import express from 'express';
import cors from 'cors';
import authRoutes from './routes/auth';
import { getLogger } from './utils/logger';

const logger = getLogger(__filename);
const app = express();

// Request logging middleware
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    logger.info(
      { method: req.method, url: req.originalUrl, status: res.statusCode, durationMs: duration },
      `HTTP ${req.method} ${req.originalUrl} - ${res.statusCode} (${duration}ms)`,
    );
  });
  next();
});

// Cross-Origin Resource Sharing: CORS_ORIGINS (comma-separated, e.g. the admin site's origin)
// limits which websites may call this API from a browser. Unset = any origin (local development).
const corsOrigins = (process.env.CORS_ORIGINS ?? '')
  .split(',')
  .map((origin) => origin.trim().replace(/\/+$/, ''))
  .filter(Boolean);
app.use(cors(corsOrigins.length ? { origin: corsOrigins } : undefined));

// Middleware to parse JSON bodies
app.use(express.json());

// Register routes
app.use('/auth', authRoutes);

// Health check route
app.get('/health', (req, res) => {
  res.json({ status: 'Auth server is running', version: process.env.GIT_SHA || 'unknown' });
});

app.use(
  (
    err: Error & { status?: number },
    req: express.Request,
    res: express.Response,
    _next: express.NextFunction,
  ) => {
    // Client errors raised by middleware (e.g. malformed JSON from express.json) carry a 4xx status
    const status = err.status && err.status >= 400 && err.status < 500 ? err.status : 500;
    logger.error(
      { err, method: req.method, url: req.originalUrl },
      `Unhandled Server Error on ${req.method} ${req.originalUrl}: ${err.message}`,
    );
    // 4xx messages are meant for the client; a 500's message may hold internals
    res.status(status).json({ error: status < 500 ? err.message : 'Internal server error' });
  },
);

export default app;
