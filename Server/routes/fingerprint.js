import express from 'express';
import Database from '../src/db.js';
import { randomUUID } from 'crypto';
import Logger from '../src/logging.js';
import UAParser from 'ua-parser-js';
import randomString from '../src/utils.js';
import * as ed from '@noble/ed25519';

const router = express.Router();
const logger = new Logger('api');

// Database init
const fingerprintDb = new Database('fingerprints.db');
await fingerprintDb.run(`
  CREATE TABLE IF NOT EXISTS devices (
    deviceId TEXT PRIMARY KEY,
    fingerprintId TEXT,
    publicKey TEXT,
    dateCreated INTEGER,
    lastUsed INTEGER
  )
`);

await fingerprintDb.run(`
CREATE TABLE IF NOT EXISTS challenges (
    deviceId TEXT PRIMARY KEY,
    challenge TEXT,
    expiresAt INTEGER
)
    `)

router.use(()=>{

    const ua = req.get('User-Agent');
    const lang = req.get('Accept-Language');
    const fp = req.get('x-fingerprint-id');

    if (!ua || !lang || !fp) {
        return res.status(400).json({ error: 'Missing headers.' });
    }

});

router.post('/register', async(req, res)=>{

    const {publicKey} = req.body;
    if (!publicKey){
        return res.status(400).json({error:"Missing/mismatch body."})
    }

    const deviceType = uaResult.device.type || 'Desktop';
    const browser = uaResult.browser.name || 'UnknownBrowser';

    const deviceId = `${deviceType}-${browser}-${randomString()}`

    await fingerprintDb.run("INSERT INTO fingerprints VALUES(?, ?, ?)", 
        [deviceId, fingerprintId, publicKey]
    );

    return res.status(200).json({deviceId:deviceId})

});

router.post('/challenge', async(req, res)=>{

    const {deviceId} = req.body;
    if (!deviceId){
        return res.status(400).json({error:"Mssing/mismatch body."});
    }

    const challengeRequested = await fingerprintDb.get(
        "SELECT challenge, expiresAt FROM fingerprints WHERE deviceId = ? LIMIT 1",
        [deviceId]
    );
    let unsignedChallenge = null;
    let expiresAt = null;
    if (challengeRequested){
        unsignedChallenge = challengeRequested.challenge;
        expiresAt = challengeRequested.expiresAt;
    }else{    
        unsignedChallenge = crypto.randomBytes(length).toString('hex');
        expiresAt = Date.now() + 30000;

        await fingerprintDb.run(
            `INSERT INTO challenges VALUES (?, ?, ?)`,
            [deviceId, unsignedChallenge, expiresAt]
        );
    }

    return res.status(200).json({challenge:unsignedChallenge, expiresAt: expiresAt})

})

router.post('/verify', async(req, res)=>{
    const {deviceId, signedChallenge} = req.body;
    if (!deviceId || typeof signedChallenge !== 'string') {
        return res.status(400).json({ error: "Missing/mismatch body." });
    }

    const userChallenges = await fingerprintDb.get(
        `SELECT challenge, expiresAt from challenges WHERE deviceId = ?`,
        [deviceId]
    );

    if (!userChallenges) {
        return res.status(400).json({ error: "Invalid challenge." });
    }
    if (userChallenges.expiresAt < Date.now()) {
        await fingerprintDb.run(
            `DELETE * FROM challenges WHERE deviceId=?`,
            [deviceId]
        );
        return res.status(400).json({ error: "Expired challenge." });
    }

    const userDevice = await fingerprintDb.get(
        `SELECT publicKey from devices WHERE deviceId = ?`,
        [deviceId]
    );

    const publicKeyBytes = Uint8Array.from(Buffer.from(userDevice.publicKey, "hex"));
    const challengeBytes = Uint8Array.from(Buffer.from(userChallenges.challenge, "hex"));
    const signatureBytes = Uint8Array.from(Buffer.from(signedChallenge, "hex"));

    const validSignature = await ed.verifyAsync(signatureBytes, challengeBytes, publicKeyBytes);
    if (!validSignature){
        return res.status(401).json({error:"Invalid signature."});
    }

    await fingerprintDb.run(
        `DELETE * FROM challenges WHERE deviceId=?`,
        [deviceId]
    );

    return res.status(200).json({success: true});


})

