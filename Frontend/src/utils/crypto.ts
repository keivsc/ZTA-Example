const { subtle } = globalThis.crypto;

interface GeneratedKey {
    privateKey: string;
    publicKey: string;
    iv: string;
    salt: string,
    rawPrivateKey?: CryptoKey;
}

interface passwordHash {
    hash: string,
    salt: string
}

export async function generateKey(password:string) : Promise<GeneratedKey>{
    
    // Derive Passwords from password
    const salt = crypto.getRandomValues(new Uint8Array(16))
    const passwordKey = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"])
    const kek = await crypto.subtle.deriveKey(
        { name: "PBKDF2", salt, iterations: 200000, hash: "SHA-256" },
        passwordKey,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );

    // Generate RSA KeyPair
    const RSAParams = {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256"
    }
    const RSAKey = await subtle.generateKey(RSAParams, true, ["encrypt", "decrypt"]);

    // Encrypt RSA Key
    const iv = crypto.getRandomValues(new Uint8Array(12));
    
    const rawRSAPublicKey = await subtle.exportKey("spki", RSAKey.publicKey)
    const encryptedRSAKey = await encryptPrivateKey(RSAKey.privateKey, kek, iv);

    return {
        privateKey: toBase64(new Uint8Array(encryptedRSAKey)),
        publicKey: toBase64(new Uint8Array(rawRSAPublicKey)),
        iv: toBase64(new Uint8Array(iv)),
        salt: toBase64(new Uint8Array(salt)),
        rawPrivateKey: RSAKey.privateKey
    };
}

export async function deriveKey(password: string, keySalt: string, keyIV: string, encryptedPrivateKey: string): Promise<GeneratedKey>{
    console.log("keySalt:", keySalt);
    const salt = fromBase64(keySalt);
    const iv = fromBase64(keyIV);
    


    const passwordKey = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"])
    const kek = await crypto.subtle.deriveKey(
        { name: "PBKDF2", salt, iterations: 200000, hash: "SHA-256" },
        passwordKey,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );

    const encryptedBytes = Uint8Array.from(atob(encryptedPrivateKey), c => c.charCodeAt(0));
    const rawPrivateKey = await decryptPrivateKey(encryptedBytes.buffer, kek, iv);

    return {
        privateKey: "",
        publicKey: "",
        salt: "",
        iv: "",
        rawPrivateKey: rawPrivateKey
    };
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


export async function encryptPrivateKey(privateKey: CryptoKey, passphrase: CryptoKey, iv:Uint8Array): Promise<ArrayBuffer> {
    const rawRSAPrivateKey = await subtle.exportKey("pkcs8", privateKey);
    const AESCBCParams = { name: 'AES-GCM', iv: iv };
    const cipherText = await subtle.encrypt(AESCBCParams, passphrase, rawRSAPrivateKey);
    return cipherText;
}

export async function decryptPrivateKey(encryptedKey: ArrayBuffer, passphrase: CryptoKey, iv: Uint8Array): Promise<CryptoKey> {
    const AESCBCParams = { name: 'AES-GCM', iv: iv };
    const decrypted = await subtle.decrypt(AESCBCParams, passphrase, encryptedKey);
    const privateKey = await importPrivateKeyFromBuffer(decrypted);
    return privateKey;
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

export async function importPrivateKeyFromBuffer(privateKey: ArrayBuffer) : Promise<CryptoKey> {
  return await crypto.subtle.importKey(
    "pkcs8", privateKey,
    {
      name: "RSA-OAEP",
      hash: "SHA-256",
    },
    true,
    ["decrypt"]
  );
}

export async function importPublicKeyFromBuffer(publicKey: ArrayBuffer) : Promise<CryptoKey>{
  return await crypto.subtle.importKey(
    "spki", publicKey,                  
    {
      name: "RSA-OAEP",
      hash: "SHA-256",
    },
    true,
    ["encrypt"]
  );
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

export async function decryptRSA(RSAPrivateKey: CryptoKey, data: string){
    return new TextDecoder().decode(await subtle.decrypt({ name: "RSA-OAEP" }, RSAPrivateKey, fromBase64(data)));
}
