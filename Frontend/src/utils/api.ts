import { bufferToHex, hexToBuffer } from "./crypto";

const apiURL = "http://localhost:3000";


// Generic Functions
export async function get(endpoint: string) {
    const URI = new URL(`${apiURL}${endpoint}`);
    const response = await fetch(URI, {
        method: 'GET',
        credentials: 'include',
    });
    return response;
}

export async function post(endpoint: string, data: any) {
    const URI = new URL(`${apiURL}${endpoint}`);
    const response = await fetch(URI, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
    });
    return response;
}


// Authentication Functions
export async function registerDevice(publicKey:string, privateKey:CryptoKey){
    const challengeRes = await post('/device/register', {publicKey});
    const challengeJSON = await challengeRes.json();
    const challengeId = challengeJSON.challengeId;
    const challenge = challengeJSON.challenge;

    const signedChallengeBuffer = await crypto.subtle.sign(
        "Ed25519",
        privateKey,
        hexToBuffer(challenge)
    )

    const signedChallenge = bufferToHex(signedChallengeBuffer);

    return await post('/device/verify', {challengeId, signedChallenge});
}

export async function checkDevice(){
    return await get('/device/check');
}

export async function checkEmailExists(email: string) {
    email = encodeURIComponent(email);
    return (await get(`/user/email/${email}`)).status == 200;
}

export async function registerUser(userData: any) {
    return await post('/user/register', userData);
}

export async function getOTPauthURL(email: string){
    email = encodeURIComponent(email);
    return (await get(`/user/totp/setup/${email}`));
}

export async function getPasswordSalt(email: string){
    email = encodeURIComponent(email);
    return await get(`/user/salt/${email}`);
}

export async function verifyHash(email: string, password: string){
    return await post('/user/login', {email:email, passwordHash: password});
}

export async function verifyChallenge(userId: string, challengeText:string){
    return await post('/user/challenge', { userId: userId, text: challengeText});
}

export async function verifyTOTP(userId: string, code:number){
    return await post('/user/totp', { userId: userId, code:code });
}
