const dbModule = require('./db');
const fingerprintDb = new dbModule('fingerprints.db');

// Make sure your table exists
(async () => {
  await fingerprintDb.run(`
    CREATE TABLE IF NOT EXISTS fingerprints (
      fingerprintId TEXT PRIMARY KEY,
      deviceId TEXT
    )
  `);
})();

async function checkFingerprint(req, res, next) {
  const deviceId = req.cookies.device_id;
  const fingerprintId = req.headers['x-fingerprint-id'];
  const url = req.url;
  const ip = req.ip;

  if (!deviceId || !fingerprintId) {
    console.log(`[${url}] ❌ Missing Auth Tokens | IP: ${ip}`);
    return res.status(400).json({ error: 'Missing Authentication Tokens' });
  }

  try {
    // Check if fingerprint exists in DB
    const storedDeviceId = await fingerprintDb.getItem(fingerprintId);

    if (storedDeviceId && storedDeviceId !== deviceId) {
      console.log(`[${url}] ⚠️ Mismatch! Expected Device ID: ${storedDeviceId}, Got: ${deviceId} | IP: ${ip}`);
      return res.status(403).json({ error: 'Authentication Tokens Mismatch' });
    }

    if (!storedDeviceId) {
      // New fingerprint-device pair, store in DB
      await fingerprintDb.setItem(fingerprintId, deviceId);
      console.log(`[${url}] 🆕 New fingerprint-device pair | Device ID: ${deviceId} | Fingerprint ID: ${fingerprintId} | IP: ${ip}`);
    } else {
      console.log(`[${url}] ✅ Known device | Device ID: ${deviceId} | Fingerprint ID: ${fingerprintId} | IP: ${ip}`);
    }

    next();
  } catch (err) {
    console.error(`[${url}] ❌ DB error`, err);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
}

module.exports = { checkFingerprint };