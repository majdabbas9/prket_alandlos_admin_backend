import express from 'express';
import authRoutes from './routes/auth';

const app = express();

// Middleware to parse JSON bodies
app.use(express.json());

// Register routes
app.use('/auth', authRoutes);

// Health check route
app.get('/health', (req, res) => {
  res.json({ status: 'Auth server is running' });
});

app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('EXPRESS ERROR:', err.stack);
  res.status(500).json({ error: err.message });
});

export default app;
