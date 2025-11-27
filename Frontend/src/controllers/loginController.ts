import { loginUser } from "../utils/api"
import { bufferToHex, generateEncryptionKeyPair, generateSigningKeyPair, hexToBuffer } from "../utils/crypto";
import { LocalDB } from "../utils/localDB";

export async function login(email: string, password: string, retries = 0){
    const payload = {email, password};
    const loginRes = await loginUser(payload);
    const loginJson = await loginRes.json();

    if(loginRes.status == 400 || loginRes.status == 500 ){
        return { code:400, message:loginJson.error };
    }

    switch(loginRes.status){
        case 200:
            return {code:200, message:"Complete."};
        case 401:
            return {code:401, userId:loginJson.userId, expiresAt:loginJson.expiresAt};
        case 419:
            if (retries >= 3) { // max 3 retries
                return {code:419, message:"Challenge expired, please retry manually."};
            }
            return login(email, password, retries + 1);
        default:
            return {code:400, message:"Internal Error."};
    }
}

