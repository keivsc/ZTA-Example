import express from 'express';
import Database from '../src/db.js';
import { randomBytes } from "crypto";
import Logger from '../src/logging.js';
import { toPEM } from '../src/utils.js'
import { encryptKey } from '../src/crypto.js';

import speakeasy from 'speakeasy';

const logger = new Logger('user')
const userDb = new Database('user.db');

router.get('/register', async (req, res)=>{
    
})