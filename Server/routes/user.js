import express from 'express';
import Database from '../src/db.js';
import { createDecipheriv, createCipheriv, randomBytes, randomUUID, sign } from "crypto";
import Logger from '../src/logging.js';
import { toPEM } from '../src/utils.js'
import { encryptKey, hashPassword } from '../src/crypto.js';
import * as ed from '@noble/ed25519';
import { generateToken, getToken } from '../services/session.js';
import dotenv from 'dotenv';

import speakeasy, { otpauthURL } from 'speakeasy';

dotenv.config({quiet:true})

const logger = new Logger('user')
const userDb = new Database('user.db');
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX_LOGIN_ATTEMPTS = 5;
const LOCK_TIME = 15 * 60 * 1000; // 15 minutes


await userDb.run(
    `CREATE TABLE IF NOT EXISTS users(
        userId TEXT PRIMARY KEY,
        username TEXT,
        email TEXT,
        passwordHash TEXT,
        passwordSalt TEXT,
        TOTPSecretEnc TEXT,
        TOTPiv TEXT,
        TOTPTag TEXT,
        loginAttempts INTEGER DEFAULT 0,
        lastLoginAttempt INTEGER
    )`
)

await userDb.run(
    `CREATE TABLE IF NOT EXISTS deviceKeys(
        deviceId TEXT PRIMARY KEY,
        userId TEXT,
        signPublic TEXT,
        encryptPublic TEXT,
        totpCheck BOOLEAN,
        createdAt INTEGER,
        lastUsed INTEGER
    )`
)

await userDb.run(
    `CREATE TABLE IF NOT EXISTS authChallenges(
        deviceId TEXT PRIMARY KEY,
        userId TEXT,
        challenge TEXT,
        nonce TEXT,
        expiresAt INTEGER
    )`
)

await userDb.run(
    `CREATE TABLE IF NOT EXISTS totp(
    deviceId TEXT PRIMARY KEY,
    userId TEXT,
    expiresAt INTEGER
    )`
)

const router = express.Router();
const AES_SECRET = Buffer.from(process.env.AES_SECRET, 'hex');

router.use((req, res, next)=>{

    const deviceId = req.cookies['x-device-id'];
    if (!deviceId){
        return res.status(400).json({error:"Missing device id."});
    }
    next();
})

router.post('/register', async (req, res)=>{
    const {username, email, password} = req.body;
    

    if (!username || !email || !password ){
        return res.status(400).json({error:"Missing username, email or password."});
    }

    if (!emailRegex.test(email)){
        return res.status(400).json({error:"Invalid email."});
    }

    const userExists = await userDb.get(
        `SELECT email FROM users WHERE email = ?`,
        [email]
    );

    if(userExists){
        return res.status(400).json({error:"Email already exists."})
    }

    const salt = randomBytes(32);
    const passwordHash = await hashPassword(password, salt);
    const totpSecret = speakeasy.generateSecret();
    const iv = randomBytes(12)
    const totpCipher = createCipheriv('aes-256-gcm', AES_SECRET, iv);
    const encryptedTotp = Buffer.concat([totpCipher.update(totpSecret.ascii, 'utf8'), totpCipher.final()]);
    const authTag = totpCipher.getAuthTag();
    const url = speakeasy.otpauthURL({secret:totpSecret.ascii, label:"ZTA Demo", algorithm:'sha512'})

    await userDb.run(
        `INSERT INTO users (userId, username, email, passwordHash, passwordSalt, TOTPSecretEnc, TOTPiv, TOTPTag)
        VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
        [randomUUID(), username, email, passwordHash.hash, salt.toString('hex'), encryptedTotp.toString('hex'), iv.toString('hex'), authTag.toString('hex')]
    );

    logger.log(`New user registered: ${email}`);

    return res.status(200).json({success:true, otpauthURL:url});

})


router.post('/login', async(req, res)=>{
    const {email, password} = req.body;
    const deviceId = req.cookies['x-device-id'];
    let userId = null;
    let keyCheck = false;
    let totp = true;

    if (!email || !password){
        return res.status(400).send({error:"Missing email or password."});
    }



    const userDevice = await userDb.get(
        `SELECT userId FROM deviceKeys WHERE deviceId = ?`,
        [deviceId]
    );
    if (userDevice){
        userId = userDevice.userId;
        totp = false;
        keyCheck = true;
    }
    
    if(!keyCheck){
        const {signPublic, encryptPublic} = req.body;
        if (!signPublic || !encryptPublic){
            return res.status(400).json({error:"Public Key missing."})
        }
        // Fetch user info including loginAttempts
        const userRecord = await userDb.get(
            `SELECT userId, passwordSalt, passwordHash, loginAttempts, lastLoginAttempt 
            FROM users WHERE email = ?`,
            [email]
        );

        if (!userRecord) {
            return res.status(400).json({ error: "User does not exist." });
        }

        // Check lockout
        if (userRecord.loginAttempts >= MAX_LOGIN_ATTEMPTS) {
            const now = Date.now();
            if (userRecord.lastLoginAttempt && (now - userRecord.lastLoginAttempt) < LOCK_TIME) {
                const remaining = Math.ceil((LOCK_TIME - (now - userRecord.lastLoginAttempt)) / 1000);
                logger.warn(`Failed login attempt for email: ${email}, deviceId: ${deviceId}`);
                return res.status(429).json({ error: `Account locked. Try again in ${remaining} seconds.` });
            } else {
                // Reset login attempts after lock period
                await userDb.run(
                    `UPDATE users SET loginAttempts = 0 WHERE userId = ?`,
                    [userRecord.userId]
                );
            }
        }

        // Verify password
        const passwordHash = await hashPassword(password, Buffer.from(userRecord.passwordSalt, "hex"));
        if (passwordHash.hash !== userRecord.passwordHash) {
            // Increment login attempts
            await userDb.run(
                `UPDATE users SET loginAttempts = loginAttempts + 1, lastLoginAttempt = ? WHERE email = ?`,
                [Date.now(), email]
            );
            return res.status(400).json({ error: "Email or password mismatch." });
        }

        userId = userRecord.userId;
        await userDb.run(
            `UPDATE users SET loginAttempts = 0, lastLoginAttempt = ? WHERE userId = ?`,
            [Date.now(), userRecord.userId]
        );
        await userDb.run(
            `INSERT INTO deviceKeys(deviceId, userId, signPublic, encryptPublic, totpCheck, createdAt, lastUsed)
            VALUES(?, ?, ?, ?, ?, ?, ?)`,
            [deviceId, userId, signPublic, encryptPublic, totp, Date.now(), null]
        );
    }



    if (!userId){
        return res.status(500).json({error:"Internal server error."});
    }

    const nonce = randomBytes(32).toString('hex');
    const challenge = randomBytes(16).toString('hex');
    const expiresAt = Date.now() + 30_000;

    const authChallenge = await userDb.get(
        `SELECT challenge, nonce FROM authChallenges WHERE deviceId = ?`,
        [deviceId]
    );
    if (authChallenge){
        return res.status(200).json({nonce:authChallenge.nonce, challenge:authChallenge.challenge});
    }

    await userDb.run(
        `INSERT INTO authChallenges(deviceId, userId, challenge, nonce, expiresAt) 
        VALUES(?,?,?,?,?)`,
        [deviceId, userId, challenge, nonce, expiresAt]
    );

    return res.status(200).json({nonce, challenge});
})

router.post('/verify', async (req, res) => {
    const { signature, nonce } = req.body;
    const deviceId = req.cookies['x-device-id'];

    if (!signature || !nonce) {
        return res.status(400).json({ error: "Missing signature or nonce." });
    }

    const deviceKeys = await userDb.get(
        `SELECT signPublic, TOTPCheck FROM deviceKeys WHERE deviceId = ?`,
        [deviceId]
    );
    
    if (!deviceKeys) {
        return res.status(400).json({ error: "Invalid device." });
    }
    const { signPublic, TOTPCheck } = deviceKeys;

    const challengeCheck = await userDb.get(
        `SELECT userId, challenge, nonce, expiresAt FROM authChallenges WHERE deviceId = ?`,
        [deviceId]
    );
    if (!challengeCheck) {
        return res.status(400).json({ error: "Invalid challenge." });
    }

    const { userId, challenge, nonce: realNonce, expiresAt } = challengeCheck;

    if (expiresAt < Date.now()) {
        await userDb.run(`DELETE FROM authChallenges WHERE deviceId = ?`, [deviceId]);
        return res.status(419).json({ error: "Challenge expired." });
    }

    if (nonce !== realNonce) {
        logger.warn(`Possible replay attack, IP: ${req.ip}`);
        return res.status(400).json({ error: "Invalid verification." });
    }

    try {
        // Import the public key for RSA-PSS
        const publicKey = await crypto.subtle.importKey(
            'spki',
            Buffer.from(signPublic, 'hex'), // your DB hex
            {
                name: 'RSA-PSS',
                hash: 'SHA-256',
            },
            true,
            ['verify']
        );

        const signatureBuffer = Buffer.from(signature, 'hex');
        const challengeBuffer = Buffer.from(challenge, 'hex');

        const validSignature = await crypto.subtle.verify(
            {
                name: 'RSA-PSS',
                saltLength: 32,
            },
            publicKey,
            signatureBuffer,
            challengeBuffer
        );

        if (!validSignature) {
            return res.status(400).json({ error: "Invalid signature." });
        }

    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: "Verification error." });
    }

    const sessionToken = await getToken(userId, deviceId, req.ip);

    if (!sessionToken || TOTPCheck) {
        await userDb.run(
            `INSERT OR IGNORE INTO totp (deviceId, userId, expiresAt) VALUES (?, ?, ?)`,
            [deviceId, userId, Date.now() + 5 * 60 * 1000]
        );
        return res.status(401).json({ error: "TOTP required.", userId, expiresAt:Date.now() + 5 * 60 * 1000});
    }

    res.cookie('session', sessionToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 60 * 60 * 1000
    });

    logger.log(`New session token for user: ${userId}`);
    return res.status(200).json({ success: true });
});


router.post('/totp',async (req,res)=>{

    const {totp, userId} = req.body;
    const deviceId = req.cookies['x-device-id'];
    if (!totp || !userId){
        return res.status(400).json({error:"Missing TOTP or userId."});
    }
    const totpValid = await userDb.get(
        `SELECT expiresAt FROM totp WHERE deviceId = ? AND userId = ?`,
        [deviceId, userId]
    );

    if(!totpValid){
        logger.warn(`Invalid TOTP request for user: ${userId}, device: ${deviceId}`);
        return res.status(400).json({error:"Invalid TOTP request."})
    }
    if (totpValid.expiresAt < Date.now()){
        await userDb.run(
            `DELETE FROM totp WHERE deviceId = ? AND userId = ?`,
            [deviceId, userId]
        )
        return res.status(400).json({error:"TOTP Request expired."})
    }

    const {TOTPSecretEnc, TOTPiv, TOTPTag} = await userDb.get(
        `SELECT TOTPSecretEnc, TOTPiv, TOTPTag FROM users WHERE userId = ?`,
        [userId]
    );

    if (!TOTPSecretEnc){
        return res.status(400).json({error:"Invalid TOTP request."})
    }

    const decipher = createDecipheriv('aes-256-gcm', AES_SECRET, Buffer.from(TOTPiv, 'hex'));
    decipher.setAuthTag(Buffer.from(TOTPTag, 'hex'));
    const decrypted = Buffer.concat([
        decipher.update(Buffer.from(TOTPSecretEnc, 'hex')),
        decipher.final()
    ]);
    const totpSecret = decrypted.toString('utf-8');

    const validTOTP = speakeasy.totp.verify({secret:totpSecret, encoding:'ascii', token:totp});
    if(!validTOTP){
        return res.status(400).json({error:"Invalid TOTP code."})
    }

    await userDb.run(
        `DELETE FROM totp WHERE deviceId = ? AND userId = ?`,
        [deviceId, userId]
    )

    const sessionToken = await generateToken(userId, deviceId);
    res.cookie('session', sessionToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 60 * 60 * 1000
    });
    logger.log(`New session token for user: ${userId}`);
    return res.status(200).json({success:true});

})

export default router;