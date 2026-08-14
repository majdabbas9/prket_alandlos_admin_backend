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
      `HTTP ${req.method} ${req.originalUrl} - ${res.statusCode} (${duration}ms)`
    );
  });
  next();
});

// Enable Cross-Origin Resource Sharing (CORS)
app.use(cors());

// Middleware to parse JSON bodies
app.use(express.json());

// Register routes
app.use('/auth', authRoutes);

// Health check route
app.get('/health', (req, res) => {
  res.json({ status: 'Auth server is running' });
});

app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  logger.error(
    { err, method: req.method, url: req.originalUrl },
    `Unhandled Server Error on ${req.method} ${req.originalUrl}: ${err.message}`
  );
  res.status(500).json({ error: err.message });
});

export default app;
