import { publicEncrypt, constants } from 'crypto';
import { toPEM } from './utils.js';

export function encryptKey(publicKey, wrapKey) {
  return publicEncrypt(
    {
      key: toPEM(Buffer.from(publicKey, "base64")),
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    Buffer.from(wrapKey)
  ).toString('base64');
}
