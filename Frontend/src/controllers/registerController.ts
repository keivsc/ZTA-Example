import { checkEmailExists, get, getOTPauthURL, registerUser } from "../utils/api";
import { decryptWrappedKeys, generateKey, hashPassword, importPrivateKeyFromBuffer } from "../utils/crypto";

interface registerResult{
    code: number;
    message: any;
    privateKey?: CryptoKey;
}

export async function Register(fullName: string, email: string, password: string) : Promise<registerResult> {
  password = password.trim();
  const pattern = new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{12,}$');
  if(!pattern.test(password)){
    return {code: 400, message: "Password Needs to be at least 12 characters long and have special characters such as '!@#$%^&*()'"};
  }

  const emailExists = await checkEmailExists(email);
  if (!emailExists) {
      return { code: 409, message: "Email already registered." };
  }

  const RSAKey = await generateKey(password);
  const hashedPassword = await hashPassword(password, crypto.getRandomValues(new Uint8Array(16)));

  const userData = {
    "username": fullName,
    "email": email,
    "publicKey": RSAKey.publicKey,
    "privateKey": RSAKey.privateKey,
    "keySalt": RSAKey.salt,
    "keyIV": RSAKey.iv,
    "passwordHash": hashedPassword.hash,
    "passwordSalt": hashedPassword.salt,
  }

  const regUser = await registerUser(userData);
  return {code: regUser.status, message:await regUser.json(), privateKey:RSAKey.rawPrivateKey}
}


export async function getTOTPSecret(email:string, privateKey: CryptoKey){
  const TOTPRes = await getOTPauthURL(email);
  if (TOTPRes.status == 200){
    const TOTPJson = await TOTPRes.json();
    return await decryptWrappedKeys(privateKey, TOTPJson.otpauthURL);
  }else{
    return "";
  }
}