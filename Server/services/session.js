import Database from '../src/db.js';
import Logger from '../src/logging.js';
import {randomBytes} from 'crypto';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken'

dotenv.config({quiet:true});

const logger = new Logger('session');
const sesDb = new Database("session.db");

await sesDb.run(`CREATE TABLE IF NOT EXISTS sessions (
    userId TEXT PRIMARY KEY,
    deviceId TEXT,
    nonce TEXT,
    expiresAt INTEGER,
    trustScore INTEGER,
    token TEXT
)`)

const HMAC_SECRET = process.env.HMAC_SECRET;
const JWT_SECRET = process.env.JWT_SECRET

export async function generateToken(userId, deviceId) {
  const nonce = crypto.randomBytes(16).toString('hex');

  // Payload object
  const payloadObj = { userId, deviceId, nonce };

  // Deterministic HMAC
  const hmac = crypto.createHmac('sha256', HMAC_SECRET)
                     .update(JSON.stringify(payloadObj))
                     .digest('hex');

  // JWT payload
  const jwtPayload = {
    payload: payloadObj,
    hmac
  };

  const sessionToken = jwt.sign(jwtPayload, JWT_SECRET, { expiresIn: '1h' });

  const expiresAt = Date.now() + 1000 * 60 * 60;

  await sesDb.run(
    `INSERT INTO sessions(userId, deviceId, nonce, expiresAt, trustScore, token)
     VALUES(?, ?, ?, ?, ?, ?)`,
    [userId, deviceId, nonce, expiresAt, 100, sessionToken]
  );

  return sessionToken;
}


export async function getToken(userId, deviceId){
    return (await sesDb.get(
        `SELECT token FROM sessions WHERE userId = ? AND deviceId = ?`,
        [userId, deviceId]
    )).token;
}


export async function verifyToken(token, deviceId){

    try {
        const tokenCheck = await sesDb.get(
            `SELECT deviceId, userId, nonce, trustScore FROM sessions WHERE token = ?`,
            [token]
        );
        if (!tokenCheck){
            throw new Error();
        }
        if (tokenCheck.trustScore < 80 || tokenCheck.deviceId !== deviceId){
            throw new Error();
        }
        const decoded = jwt.verify(token, JWT_SECRET);
        const expectedHmac = crypto.createHmac('sha256', HMAC_SECRET)
                                .update(JSON.stringify(decoded.payload))
                                .digest('hex');
        if (decoded.hmac !== expectedHmac) throw new Error();
        if (decoded.payload.userId !== tokenCheck.userId) throw new Error();
    } catch (_) {
        await sesDb.run(`DELETE FROM sessions WHERE token = ?`, [token]);
        return false;
    }

    return decoded.payload.userId;

}

export async function updateTrustScore(token, deviceId, score){

    const verified = await verifyToken(token, deviceId);
    if (!verified) return false;

    await sesDb.run(
        `UPDATE sessions
        SET trustScore = MIN(100, MAX(0, trustScore + ?))
        WHERE token = ?
        `,
        [score, token]
    );

    return true;

}