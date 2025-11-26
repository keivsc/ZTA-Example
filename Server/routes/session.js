import express from 'express';
import Database from '../src/db.js';
import { randomBytes } from "crypto";
import Logger from '../src/logging.js';
import { toPEM } from '../src/utils.js'
import { encryptKey } from '../src/crypto.js';

import speakeasy from 'speakeasy';

const logger = new Logger('session');

const sesDB = new Database("session.db");

await sesDB.run(`CREATE TABLE IF NOT EXISTS Sessions (
    userId TEXT PRIMARY KEY,
    deviceId TEXT,
    expiresAt INTEGER,
    trustScore INTEGER,
    token TEXT
)`)

const router = express.Router();

router.use('/get', async(req, res)=>{
    {}
})