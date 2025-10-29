import express from 'express';
import { randomUUID } from 'crypto';
import Database from '../src/db.js';
import Logger from '../src/logging.js';

const router = express.Router();
const logger = new Logger('api');

// Database init
const fingerprintDb = new Database('fingerprints.db');
await fingerprintDb.run(`
  CREATE TABLE IF NOT EXISTS fingerprints (
    fingerprintId TEXT PRIMARY KEY,
    deviceId TEXT,
    userId TEXT
  )
`);

// Middleware to validate fingerprint/deviceID (except for /fingerprint itself)
router.use(async (req, res, next) => {
  if (req.path === '/fingerprint' && req.method === 'POST') return next();

  const deviceId = req.cookies.device_id;
  const fingerprintId = req.headers['x-fingerprint-id'];

  if (!deviceId || !fingerprintId) {
    logger.warn(`[/api${req.url}] Missing Auth Tokens | IP: ${req.ip}`);
    return res.status(403).json({ 403: 'Forbidden' });
  }

  try {
    const stored = await fingerprintDb.getOne(
      'SELECT deviceId FROM fingerprints WHERE fingerprintId = ?',
      [fingerprintId],
      row => row.deviceId
    );

    if (stored && stored !== deviceId) {
      logger.warn(`[${req.url}] Mismatch! Expected Device ID: ${stored}, Got: ${deviceId} | IP: ${req.ip}`);
      return res.status(403).json({ error: 'Authentication Tokens Mismatch' });
    }

    next();
  } catch (err) {
    logger.error(`[${req.url}] DB error`, err);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

// POST /api/fingerprint
router.post('/fingerprint', async (req, res) => {
  let deviceId = req.cookies.device_id;
  const fingerprintId = req.body?.['x-fingerprint-id'];

  if (!fingerprintId) {
    logger.warn(`[${req.url}] Suspicious Request (Bot) | IP: ${req.ip}`);
    return res.status(400).json({ 403: 'Forbidden' });
  }

  if (!deviceId) {
    const newId = randomUUID();
    res.cookie('device_id', newId, {
      httpOnly: false,
      sameSite: 'lax',
      maxAge: 1000 * 60 * 60 * 24 * 365,
    });
    deviceId = newId;
    logger.info(`Assigned new device ID: ${newId} | IP: ${req.ip}`);
  }

  try {
    const stored = await fingerprintDb.getOne(
      'SELECT deviceId FROM fingerprints WHERE fingerprintId = ?',
      [fingerprintId],
      row => row.deviceId
    );

    if (stored && stored !== deviceId) {
      logger.warn(`[${req.url}] Mismatch! Expected Device ID: ${stored}, Got: ${deviceId} | IP: ${req.ip}`);
      return res.status(403).json({ error: 'Authentication Tokens Mismatch' });
    }

    if (!stored) {
      await fingerprintDb.run(
        'INSERT INTO fingerprints (fingerprintId, deviceId, userId) VALUES (?, ?, ?)',
        [fingerprintId, deviceId, null]
      );
      logger.info(`[${req.url}] New fingerprint-device pair | Device ID: ${deviceId} | Fingerprint ID: ${fingerprintId} | IP: ${req.ip}`);
    }

    return res.json({
      deviceId,
      status: stored ? 'verified' : 'new',
    });

  } catch (err) {
    logger.error(`[${req.url}] DB error`, err);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

// GET /api/data
router.get('/data', async (req, res) => {
  res.json({ message: 'Hello from the backend!' });
});

export default router;