import express from 'express';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import dotenv from 'dotenv';
import rateLimiter from 'express-rate-limit';
import Logger from './src/logging.js';

import userRoutes from './routes/user.js';
import apiRoutes from './routes/api.js';

dotenv.config();
const logger = new Logger('main');

const app = express();
const PORT = 3000;

const apiLimiter = rateLimiter({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests, please try again later.',
});

const fingerprintLimiter = rateLimiter({
  windowMs: 60 * 1000,
  max: 5,
  message: 'Too many fingerprint requests, please try again later.',
});

// Middleware setup
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5173',
  credentials: true,
}));
app.use(cookieParser());
app.use(express.json());

// Apply rate limiting
app.use('/api/', apiLimiter);
app.use('/api/fingerprint', fingerprintLimiter);

// Routes
app.use('/user', userRoutes);
app.use('/api', apiRoutes);


// Start server
app.listen(PORT, () => {
  logger.info(`Express server running on http://localhost:${PORT}`);
});