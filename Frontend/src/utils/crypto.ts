import { LocalDB } from "./localDB";

const { subtle } = globalThis.crypto;


interface passwordHash {
    hash: string,
    salt: string
}

export async function generateEncryptionKeyPair() : Promise<CryptoKeyPair>{

    const RSAParams = {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256"
    }
    const RSAKey = await subtle.generateKey(RSAParams, true, ["encrypt", "decrypt"]);

    return RSAKey;
}

export async function generateSigningKeyPair(): Promise<CryptoKeyPair> {
    const RSAParams = {
        name: "RSA-PSS",               // Use "RSASSA-PKCS1-v1_5" if you prefer
        modulusLength: 2048,           // Standard secure length
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256"                // Hash algorithm for signing
    };

    const RSAKey = await subtle.generateKey(
        RSAParams,
        true,                          // extractable
        ["sign", "verify"]             // key usages for signing
    );

    return RSAKey;
}



export async function hashPassword(password: string, salt:Uint8Array<ArrayBuffer>): Promise<passwordHash>{

    // Import PassKey
    const passKey = await subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);

    // Derive Key
    const derivedBits = await subtle.deriveBits({name: "PBKDF2", salt, iterations:200000, hash: "SHA-256"}, passKey, 256);

    return {
        hash: toBase64(new Uint8Array(derivedBits)),
        salt: toBase64(new Uint8Array(salt))
    }

}

export function toBase64(uint8arr: Uint8Array) {
  let binary = '';
  const chunkSize = 0x8000; // 32KB chunks
  for (let i = 0; i < uint8arr.length; i += chunkSize) {
    binary += String.fromCharCode(...uint8arr.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

export function fromBase64(base64: string) {
  return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}


export async function decryptWrappedKeys(privateKey: CryptoKey, encryptedKey: string): Promise<string> {
    try {
        const keyBuffer = Uint8Array.from(atob(encryptedKey), c => c.charCodeAt(0)).buffer;
        const decryptedKey = await crypto.subtle.decrypt(
            { name: 'RSA-OAEP' },
            privateKey,
            keyBuffer
        );

        return new TextDecoder().decode(decryptedKey);
    } catch (err) {
        console.error("Decryption failed:", err);
        return "";
    }
}


export async function generateDeviceKey() {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "Ed25519"
    },
    true,                 // extractable
    ["sign", "verify"]    // usages
  );

  return keyPair;
}
export function bufferToHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

export function hexToBuffer(hex: string): ArrayBuffer {
  if (hex.length % 2 !== 0) {
    throw new Error("Invalid hex string length");
  }

  const length = hex.length / 2;
  const buffer = new Uint8Array(length);

  for (let i = 0; i < length; i++) {
    buffer[i] = parseInt(hex.substr(i * 2, 2), 16);
  }

  return buffer.buffer;
}





export interface DeviceKeys {
    sign: { publicKey: string; privateKey: string; CryptoPrivateKey: CryptoKey };
    encrypt: { publicKey: string; privateKey: string; CryptoPrivateKey: CryptoKey };
}

export async function getDeviceKeys(): Promise<DeviceKeys> {
    const db = new LocalDB('ZTA-Example', 2);

    // Try to get existing keys
    const existingKey: any = await db.getItem('authKeys', 'myDevice');

    let signKey: DeviceKeys['sign'];
    let encryptKey: DeviceKeys['encrypt'];

    // --- Signing key ---
    if (existingKey?.sign) {
        const privateKey = await crypto.subtle.importKey(
            'pkcs8',
            hexToBuffer(existingKey.sign.privateKey),
            { name: "RSA-PSS",
              hash: { name:"SHA-256" }
             },
            true,
            ['sign']
        );
        signKey = {
            publicKey: existingKey.sign.publicKey,
            privateKey: existingKey.sign.privateKey,
            CryptoPrivateKey: privateKey
        };
    } else {
        const signingKeys = await generateSigningKeyPair();
        const rawPrivateKey = await crypto.subtle.exportKey("pkcs8", signingKeys.privateKey);
        const rawPublicKey = await crypto.subtle.exportKey("spki", signingKeys.publicKey);

        signKey = {
            privateKey: bufferToHex(rawPrivateKey),
            publicKey: bufferToHex(rawPublicKey),
            CryptoPrivateKey: signingKeys.privateKey
        };
    }

    // --- Encryption key ---
    if (existingKey?.encrypt) {
        const privateKey = await crypto.subtle.importKey(
            'pkcs8',
            hexToBuffer(existingKey.encrypt.privateKey),
            { name: "RSA-OAEP",
              hash: { name:"SHA-256" }
             },
            true,
            ['decrypt']
        );
        encryptKey = {
            publicKey: existingKey.encrypt.publicKey,
            privateKey: existingKey.encrypt.privateKey,
            CryptoPrivateKey: privateKey
        };
    } else {
        const encryptionKeys = await generateEncryptionKeyPair();
        const rawPrivateKey = await crypto.subtle.exportKey("pkcs8", encryptionKeys.privateKey);
        const rawPublicKey = await crypto.subtle.exportKey("spki", encryptionKeys.publicKey);

        encryptKey = {
            privateKey: bufferToHex(rawPrivateKey),
            publicKey: bufferToHex(rawPublicKey),
            CryptoPrivateKey: encryptionKeys.privateKey
        };
    }

    // --- Save any newly generated keys back to IndexedDB ---
    if (!existingKey || !existingKey.sign || !existingKey.encrypt) {
        await db.addItem('authKeys', { id: 'myDevice', value: { sign: signKey, encrypt: encryptKey } });
    }

    return { sign: signKey, encrypt: encryptKey };
}