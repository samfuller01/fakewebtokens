const crypto = require('crypto');

// Internal functions
encrypt = (data, publicKey) => {
  // Returns a buffer
  return crypto.publicEncrypt({
    key: publicKey,
    oaepHash: 'sha1',
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
  }, Buffer.from(data));
};

decrypt = (encryptedData, privateKey) => {
  // Returns decrypted value as a string
  return crypto.privateDecrypt({
    key: privateKey,
    oaepHash: 'sha1',
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
  }, Buffer.from(encryptedData, 'base64')).toString();
};

// WIP - for switch from encrypt/decrypt to sign/verify
sign = (data, privateKey) => {
  // Returns Buffer
  return crypto.sign('sha1', Buffer.from(data), {
    key: privateKey,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING
  });
};

verifySign = (secret, publicKey, signature) => {
  // Returns Boolean
  return crypto.verify('sha1', secret, {
    key: publicKey,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING
  }, signature);
};

// All functions above this are helper functions -- not exported
// All functions below this are exported

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
  });
  return {
    publicKey: keys.publicKey,
    privateKey: keys.privateKey
  };
};

// Default key's assuming none are passed in
const { publicKey, privateKey } = generateKeys(2048);

// Generate a token
generateToken = (payload, secret, expireTime, keys = null) => { 
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
    // If no keys are passed in as an Object
    if (keys !== null) { 
      // Check that the keys exist
      if (keys.publicKey === null || keys.privateKey === null) {
        reject('Keys must be an Object containing the public key and private key as strings');
      }
      const token = `${sign(secret, keys.privateKey).toString('base64')}.${encrypt(stringPayload, keys.publicKey).toString('base64')}.${encrypt(encryptTime.toString(), keys.publicKey).toString('base64')}`;
      resolve(token);
    } else { 
      // No optional keys passed in - use default keys
      const token = `${sign(secret, privateKey).toString('base64')}.${encrypt(stringPayload, publicKey).toString('base64')}.${encrypt(encryptTime.toString(), publicKey).toString('base64')}`;
      resolve(token);
    }
  });
};

// Verify a token's signature
verifyToken = (token, secret, keys = null) => {
  return new Promise((resolve, reject) => {
    const splitToken = token.split('.');
    const header = splitToken[0];
    const payload = splitToken[1];
    const expireTime = splitToken[2];

    if (keys !== null) {
      if (keys.publicKey === null || keys.privateKey === null) {
        reject('Invalid custom keys');
      }
      if (!verifySign(Buffer.from(secret), keys.publicKey, Buffer.from(header, 'base64'))) {
        reject('Invalid Token');
      }
      if (Date.now().toString() > decrypt(expireTime, keys.privateKey)) {
        reject('Token has expired');
      }
      const decryptedPayload = JSON.parse(decrypt(payload, keys.privateKey));
      if (typeof decryptedPayload !== 'object') {
        reject('Invalid Payload');
      }
      resolve(decryptedPayload);
    }

    if (!verifySign(Buffer.from(secret), publicKey, Buffer.from(header, 'base64'))) {
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
};

// Decode a token payload
decodeToken = (token, keys = null) => {
  return new Promise((resolve, reject) => {
    const payload = token.split('.')[1];
    if (keys !== null && keys.privateKey !== null) {
      const decrypted = JSON.parse(decrypt(payload, keys.privateKey));
      if (typeof decrypted !== 'object') {
        reject('Payload is not an object');
      }
      resolve(decrypted);
    }
    const decrypted = JSON.parse(decrypt(payload, privateKey));
    if (typeof decrypted !== 'object') {
      reject('Payload is not an object');
    }
    resolve(decrypted);
  });
};

// Sync token functions

// Generate a token
generateTokenSync = (payload, secret, expireTime, keys = null) => {
  // Type checking
  if (typeof expireTime !== 'number') {
    throw 'Expire time must be a number';
  }
  if (typeof payload !== 'object') {
    throw 'Payload must be an object';
  }
  if (typeof secret !== 'string') {
    throw 'Secret must be a string';
  }
  const stringPayload = JSON.stringify(payload);
  const encryptTime = Date.now() + expireTime;
  // If no keys are passed in as an Object
  if (keys !== null) { 
    // Check that the keys exist
    if (keys.publicKey === null || keys.privateKey === null) {
      throw 'Keys must be an Object containing the public key and private key as strings';
    }
    const token = `${sign(secret, keys.privateKey).toString('base64')}.${encrypt(stringPayload, keys.publicKey).toString('base64')}.${encrypt(encryptTime.toString(), keys.publicKey).toString('base64')}`;
    return token;
  } else { 
    // No optional keys passed in - use default keys
    const token = `${sign(secret, privateKey).toString('base64')}.${encrypt(stringPayload, publicKey).toString('base64')}.${encrypt(encryptTime.toString(), publicKey).toString('base64')}`;
    return token;
  }
};

verifyTokenSync = (token, secret, keys = null) => {
  const splitToken = token.split('.');
  const header = splitToken[0];
  const payload = splitToken[1];
  const expireTime = splitToken[2];

  if (keys !== null) {
    if (keys.publicKey === null || keys.privateKey === null) {
      throw 'Invalid custom keys';
    }

    if (!verifySign(Buffer.from(secret), keys.publicKey, Buffer.from(header, 'base64'))) {
      return false;
    }
    if (Date.now().toString() > decrypt(expireTime, keys.privateKey)) {
      return false;
    }
    const decryptedPayload = JSON.parse(decrypt(payload, keys.privateKey));
    if (typeof decryptedPayload !== 'object') {
      return false;
    }
    return true;
  }

  if (!verifySign(Buffer.from(secret), publicKey, Buffer.from(header, 'base64'))) {
    return false;
  }
  if (Date.now().toString() > decrypt(expireTime, privateKey)) {
    return false;
  }
  const decryptedPayload = JSON.parse(decrypt(payload, privateKey));
  if (typeof decryptedPayload !== 'object') {
    return false;
  }
  return true;
};

decodeTokenSync = (token, keys = null) => {
  const payload = token.split('.')[1];
  if (keys !== null && keys.privateKey !== null) {
    const decrypted = JSON.parse(decrypt(payload, keys.privateKey));
    if (typeof decrypted !== 'object') {
      throw 'Token payload is not an object';
    }
    return decrypted;
  }
  const decrypted = JSON.parse(decrypt(payload, privateKey));
  if (typeof decrypted !== 'object') {
    throw 'Token payload is not an object';
  }
  return decrypted;
};


module.exports = {
  generateToken,
  generateTokenSync,
  verifyToken,
  verifyTokenSync,
  decodeToken,
  decodeTokenSync,
  generateKeys
};
