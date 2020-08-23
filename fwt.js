const crypto = require('crypto');

// IMPORTANT: Format of FWT's
// [header].[payload].[expireTime]
// header is going to be signed/verified using the secret
// payload and expire time are just going to be encrypted/decrypted
// I'm not going to sign everything in order to keep the JWT like 
// token structure

generateKeys = (modulusLength) => {
  const keys = crypto.generateKeyPairSync('rsa', {
    modulusLength: modulusLength,
    publicKeyEncoding: {
      type: 'pkcs1',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs1',
      format: 'pem'
    }
  })
  return {
    publicKey: keys.publicKey,
    privateKey: keys.privateKey
  };
}

const { publicKey, privateKey } = generateKeys(2048);

// Use RSA encoding algorithm for encryption/decryption
// I had issues with signing/verifying tokens so in the future
// encrypt/decrypt will be replaced with signing/verifying
encrypt = (data, publicKey) => {
  // Returns a buffer
  return crypto.publicEncrypt({
    key: publicKey,
    oaepHash: 'sha1',
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
  }, Buffer.from(data));
}

decrypt = (encryptedData, privateKey) => {
  // Returns decrypted value as a string
  return crypto.privateDecrypt({
    key: privateKey,
    oaepHash: 'sha1',
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
  }, Buffer.from(encryptedData, 'base64')).toString();
}

// WIP - for switch from encrypt/decrypt to sign/verify
sign = (data, privateKey) => {
  // Returns Buffer
  return crypto.sign('sha1', Buffer.from(data), {
    key: privateKey,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING
  });
}

verifySign = (secret, publicKey, signature) => {
  // Returns Boolean
  return crypto.verify('sha1', secret, {
    key: publicKey,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING
  }, signature);
}

// All functions above this are helper functions -- not exported
// All functions below this are promise based

// Generate a token
generateToken = (payload, secret, expireTime) => { 
  return new Promise((resolve, reject) => {
    // Type checking
    if (typeof expireTime !== 'number') {
      reject('Expire time must be a number');
    }
    if (typeof payload !== 'object') {
      reject('Payload must be an object');
    }
    if (typeof secret !== 'string') {
      reject('Secret must be a string');
    }
    const stringPayload = JSON.stringify(payload);
    const encryptTime = Date.now() + expireTime;
    const token = `${sign(secret, privateKey).toString('base64')}.${encrypt(stringPayload, publicKey).toString('base64')}.${encrypt(encryptTime.toString(), publicKey).toString('base64')}`;
    resolve(token);
  });
}

// Verify a token's signature
verifyToken = (token, secret) => {
  return new Promise((resolve, reject) => {
    const splitToken = token.split('.');
    const header = splitToken[0];
    const payload = splitToken[1];
    const expireTime = splitToken[2];

    if (verifySign(Buffer.from(secret), publicKey, Buffer.from(header)) === true) {
      reject('Invalid Token');
    }
    if (Date.now().toString() > decrypt(expireTime, privateKey)) {
      reject('Token has expired');
    }
    const decryptedPayload = JSON.parse(decrypt(payload, privateKey));
    if (typeof decryptedPayload !== 'object') {
      reject('Invalid Payload');
    }
    resolve(decryptedPayload);
  });
}

// Decode a token payload
decodeToken = (token) => {
  return new Promise((resolve, reject) => {
    const payload = token.split('.')[1];
    const decrypted = JSON.parse(decrypt(payload, privateKey));
    if (typeof decrypted !== 'object') {
      reject('Payload is not an object');
    }
    resolve(decrypted);
  });
}

module.exports = {
  generateToken,
  verifyToken,
  decodeToken,
  generateKeys
};
