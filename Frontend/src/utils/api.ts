import { bufferToHex, getDeviceKeys, hexToBuffer } from "./crypto";

// const apiURL = "http://localhost:3000";
const apiURL = "https://airlines-lectures-range-properly.trycloudflare.com"

// Generic Functions
const DEFAULT_TIMEOUT = 10000; // 10 seconds

interface ApiResponse {
  status: number;
  json: () => Promise<any>;
}

export interface FileItem {
  fileId: string;
  filename: string;
  size: number;
  canRead: boolean;
  canWrite: boolean;
}

export type userPermission = { 
    userId:string, 
    canRead:boolean, 
    canWrite:boolean 
}

export type user = {
    userId:string,
    name:string
}

export async function get(endpoint: string, timeout = DEFAULT_TIMEOUT): Promise<ApiResponse> {
    const URI = new URL(`${apiURL}${endpoint}`);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    try {
        const response = await fetch(URI, {
            method: 'GET',
            credentials: 'include',
            signal: controller.signal,
        });
        return response;
    } catch (err: any) {
        if (err.name === 'AbortError') {
            return {
                status: 408, // 408 = Request Timeout
                json: async () => ({ statusCode: 408, error: `GET ${endpoint} timed out after ${timeout}ms` }),
            };
        }
        return {
            status: 500,
            json: async () => ({ statusCode: 500, error: `GET ${endpoint} failed: ${err.message}` }),
        };
    } finally {
        clearTimeout(timer);
    }
}

export async function post(endpoint: string, data: any, timeout = DEFAULT_TIMEOUT): Promise<ApiResponse> {
    const URI = new URL(`${apiURL}${endpoint}`);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    try {
        const response = await fetch(URI, {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data),
            signal: controller.signal,
        });
        return response;
    } catch (err: any) {
        if (err.name === 'AbortError') {
            return {
                status: 408,
                json: async () => ({ statusCode: 408, error: `POST ${endpoint} timed out after ${timeout}ms` }),
            };
        }
        return {
            status: 500,
            json: async () => ({ statusCode: 500, error: `POST ${endpoint} failed: ${err.message}` }),
        };
    } finally {
        clearTimeout(timer);
    }
}

export async function put(endpoint: string, data: any, timeout = DEFAULT_TIMEOUT): Promise<ApiResponse> {
    const URI = new URL(`${apiURL}${endpoint}`);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    try {
        const response = await fetch(URI, {
            method: 'PUT',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data),
            signal: controller.signal,
        });
        return response;
    } catch (err: any) {
        if (err.name === 'AbortError') {
            return {
                status: 408,
                json: async () => ({ statusCode: 408, error: `POST ${endpoint} timed out after ${timeout}ms` }),
            };
        }
        return {
            status: 500,
            json: async () => ({ statusCode: 500, error: `POST ${endpoint} failed: ${err.message}` }),
        };
    } finally {
        clearTimeout(timer);
    }
}



// Authentication Functions
export async function registerDevice(publicKey:string, privateKey:CryptoKey){
    const challengeRes = await post('/device/register', {publicKey});
    if (challengeRes.status != 200){
        return challengeRes;
    }
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

export async function registerUser(userData: {username:string; email: string; password: string}) {
    return await post('/user/register', userData);
}

export async function loginUser(userData:{email: string; password: string}){
    const keys = await getDeviceKeys();
    const payload = {email:userData.email, password:userData.password, signPublic:keys.sign.publicKey, encryptPublic:keys.encrypt.publicKey};
    const loginRes = await post('/user/login', payload);
    if (loginRes.status != 200){
        return loginRes;
    }

    const loginJson = await loginRes.json();
    const challenge = loginJson.challenge;
    const nonce = loginJson.nonce;

    const signedChallengeBuffer = await crypto.subtle.sign(
    { name: "RSA-PSS", saltLength: 32 },
    keys.sign.CryptoPrivateKey,
    hexToBuffer(challenge)
    );

    const signedChallenge = bufferToHex(signedChallengeBuffer);
    return await post('/user/verify', {signature:signedChallenge, nonce});
}

export async function verifyTOTP(userId:string, totp:Number){
    return await post('/user/totp', {userId, totp});
}

export async function getFile(fileId:string){
    const encodedFileId = encodeURIComponent(fileId);
    const fileRes = await get('/file/'+encodedFileId);
    if (fileRes.status != 200){
        return "";
    }
    return await fileRes.json();
}

export async function getAllFiles(): Promise<FileItem[]> {
  try {
    const response = await get('/file/all');

    if (response.status !== 200) {
      return [];
    }

    const data: { files: FileItem[] } = await response.json();
    return data.files ?? [];
  } catch (err) {
    console.error("Failed to fetch files:", err);
    return [];
  }
}

export async function createFile(filename:string, users?:userPermission[]){
    return await post('/file/create', {filename, users});
}

export async function modifyFile(fileId: string, content:string){
    const encodedFileId = encodeURIComponent(fileId);
    return await put(`/file/modify/${encodedFileId}`, {content});
}