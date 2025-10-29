export function toPEM(base64Key) {
  // Decode from base64 back to binary
  const der = Buffer.from(base64Key, 'base64');

  // Convert to PEM
  const b64 = der.toString('base64');
  const pem =
    `-----BEGIN PUBLIC KEY-----\n` +
    b64.match(/.{1,64}/g).join('\n') +
    `\n-----END PUBLIC KEY-----`;

  return pem;
}
