import express from 'express';
import Database from '../src/db.js';
import { createCipheriv, randomBytes, randomUUID, sign } from "crypto";
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
        publicKey TEXT,
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

router.use((req,res)=>{
    const deviceId = req.cookies['x-device-id'];
    if (!deviceId){
        return res.status(400).json({error:"Missing device id."});
    }

})

router.get('/register', async (req, res)=>{
    const {username, email, password} = req.body;
    

    if (!username || !email || !password ){
        return res.status(400).json({error:"Missing username, email or password."});
    }

    const userExists = await userDb.get(
        `SELECT email FROM users WHERE email = ?`,
        [email]
    );

    if(userExists){
        return res.status(400).json({error:"Email already exists."})
    }

    const salt = randomBytes(32);
    const passwordHash = hashPassword(password, salt);
    const totpSecret = speakeasy.generateSecret();
    const iv = randomBytes(12)
    const totpCipher = createCipheriv('aes-256-gcm', env.AES_SECRET, iv);
    const encryptedTotp = Buffer.concat([cipher.update(totpSecret.ascii, 'utf8'), cipher.final()]);
    const authTag = totpCipher.getAuthTag();
    const url = speakeasy.otpauthURL({secret:totpSecret.ascii, label:"ZTA Demo", algorithm:'sha512'})

    await userDb.run(
        `INSERT INTO users (userId, username, email, passwordHash, passwordSalt, TOTPSecretEnc, TOTPiv, TOTPTag)
        VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
        [randomUUID(), username, email, passwordHash, salt.toString('hex'), encryptedTotp.toString('hex'), iv.toString('hex'), authTag.toString('hex')]
    );

    return res.status(200).json({success:true, otpauthURL:url});

})


router.post('/login', async(req, res)=>{
    const {email, password} = req.body;
    const deviceId = req.cookies['x-device-id'];
    let userId = null;
    let totp = true;
    let keyCheck = false;

    if (!email || !password){
        return res.status(400).send({error:"Missing email or password."});
    }



    const userDevice = await userDb.get(
        `SELECT userId FROM deviceKeys WHERE deviceId = ?`,
        [deviceId]
    );
    if (userDevice){
        userId = userDevice.userId;
        keyCheck = true;
        totp=false;
    }
    
    if(!keyCheck){
        const {publicKey} = req.body;
        if (!publicKey){
            return res.status(400).json({error:"Public Key missing."})
        }
        const userSalt = await userDb.get(
            `SELECT passwordSalt FROM users WHERE email=?`
        )

        if (!userSalt){
            return res.status(400).json({error:"User does not exist."});
        }

        const passwordHash = await hashPassword(password, Buffer.from(userSalt.passwordSalt, "hex"));

        const auth = await userDb.get(
            `SELECT userId FROM users WHERE email = ? AND passwordHash = ?`,
            [email, passwordHash.hash]
        );

        if(!auth){
            return res.status(400).json({error:"Email or password mismatch."})
        }

        userId = auth.userId;

        await userDb.run(
            `INSERT INTO deviceKeys(deviceId, userId, publicKey, totpCheck createdAt, lastUsed)
            VALUES(?,?,?,?,?,?)`,
            [deviceId, userId, publicKey, totp, Date.now(), null]
        );
        
    }

    if (!userId){
        return res.status(500).json({error:"Internal server error."});
    }

    const nonce = randomBytes(32).toString('hex');
    const challenge = randomBytes(16).toString('hex');
    const expiresAt = Date.now() + 30_000;

    await userDb.run(
        `INSERT INTO authChallenges(deviceId, userId, challenge, nonce, expiresAt) 
        VALUES(?,?,?,?,?)`,
        [deviceId, userId, challenge, nonce, expiresAt]
    );

    return res.status(200).json({nonce, challenge});

})

router.post('/verify', async(req, res)=>{
    const {signature, nonce} = req.body;
    const deviceId = req.cookies['x-device-id'];

    if (!signature || !nonce){
        return res.status(400).json({error:"Missing signature or nonce."});
    }

    const {publicKey, TOTPCheck} = await userDb.get(
        `SELECT publicKey, TOTPCheck FROM deviceKeys WHERE deviceId = ?`,
        [deviceId]
    );
    if(!publicKey){
        return res.status(400).json({error:"Invalid device."})
    }

    const challengeCheck = await userDb.get(
        `SELECT userId, challenge, nonce, expiresAt FROM authChallenges WHERE deviceId = ?`,
        [deviceId]
    );
    if(!challengeCheck){
        return res.status(400).json({error:"Invalid challenge."});
    }

    const userId = challengeCheck.userId;
    const challenge = challengeCheck.challenge;
    const realNonce = challengeCheck.nonce;
    const expiresAt = challengeCheck.expiresAt;

    if (expiresAt < Date.now()){
        await userDb.run(
            `DELETE FROM authChallenges WHERE deviceId = ?`,
            [deviceId]
        );
        return res.status(400).json({error:"Challenge expired."})
    }

    if (nonce !== realNonce){
        logger.warn(`Possible replay attack, IP: ${req.ip}`);
        return res.status(400).json({error:"Invalid verification."})
    }

    const signatureBytes = Buffer.from(signature, 'hex');
    const challengeBytes = Buffer.from(challenge, 'utf-8');

    const validSignature = await ed.verifyAsync(signatureBytes, challengeBytes, publicKey);

    if (!validSignature){
        return res.status(400).json({error:"Invalid signature."})
    }
    const sessionToken = await getToken(userId, deviceId);
    
    if (!sessionToken || TOTPCheck){
        await userDb.run(
            `INSERT INTO totp (deviceId, userId, expiresAt)
            VALUES(?,?,?,?)`,
            [deviceId, userId, Date.now()+60000 * 5]
        );
        return res.status(401).json({ error:"TOTP required.", userId });
    }

    res.cookie('session', sessionToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 60 * 60 * 1000
    });

    return res.status(200).json({ success: true });
    
})

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
        return res.status(400).json({error:"Invalid TOTP request."})
    }
    if (totpValid.expiresAt < Date.now()){
        await userDb.run(
            `DELETE FROM totp WHERE deviceId = ? AND userId = ?`,
            [deviceId, userId]
        )
        return res.status(400).json({error:"TOTP Request expired."})
    }

    const {totpSecretEnc, totpIV, totpTag} = await userDb.get(
        `SELECT TOTPSecretEnc, TOTPiv, TOTPTag FROM users WHERE userId = ?`,
        [userId]
    );

    if (!totpSecretEnc){
        return res.status(400).json({error:"Invalid TOTP reqest."})
    }

    const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(env.AES_SECRET, 'hex'), Buffer.from(totpIV, 'hex'));
    decipher.setAuthTag(Buffer.from(totpTag, 'hex'));
    const decrypted = Buffer.concat([
        decipher.update(Buffer.from(totpSecretEnc, 'hex')),
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
    return res.status(200).json({success:true});

})

export default router;