# fakewebtokens
[![Build Status](https://travis-ci.com/samfuller01/fakewebtokens.svg?branch=master)](https://travis-ci.com/samfuller01/fakewebtokens)  
A reimplementation of JSON Web Tokens in pure JavaScript.

# Use Case
This project was simply for fun. This code is not designed to be used where security is of the essence(ie a production codebase). 
If you are interested in token based authentication in a production environment you should probably use [JWT's](https://jwt.io/).

## Installation
Want to mess around with this code (**OUTSIDE OF A PRODUCTION CODEBASE**)? Here's how:
```bash
git clone https://github.com/samfuller01/fakewebtokens.git
cd fakewebtokens
```

To include in a project (assuming your project is in the same directory as `fwt.js`):
```js
const fwt = require('./fwt');
// OR
import { generateToken, verifyToken, decodeToken } from './fwt';
```

## Token Structure
There are some key differences between the structure of my tokens and JWT's tokens.  
JWT: `[header].[payload].[signature]`  
  - JWT's header is used to specify the algorithm and token type
  - JWT's payload is an encrypted JSON object. If the token has an expire time it is also stored here.
  - JWT's signature takes the secret and signs it for use with ensuring authenticity
    
FWT: `[signature].[payload].[expireTime]`  
  - FWT's signature is stored where JWT's header is. I sign the secret with an RSA signature
  - FWT's payload is almost exactly the same as JWT's. The only difference is FWT requires that tokens expire, while JWT doesn't.
  - FWT's expire time is stored here. This is required.

## Documentation
There are seven functions that are exported by `fwt.js`. You can either use the default keys generated by `fwt.js` that have a modulus length of 2048 or you can create your own custom keys using `fwt.generateKeys(modulusLength)`. If you decide to use custom keys you must pass them into every single function. E.g: A token generated with custom keys cannot be verified with default keys(assuming the modulus length is different).

### generateToken(payload, secret, expireTime[, keys])
This is used to generate a token. It returns a Promise with the token.
> Note: expireTime represents how many milliseconds the token should be valid.
  - payload - [`Object`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Working_with_Objects)
  - secret - [`string`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Data_structures#String_type)
  - expireTime - [`number`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Data_structures#Number_type)
  - keys - **Optional** - [`Object`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Working_with_Objects)
    - `keys.publicKey` - [`string`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Data_structures#String_type) Public key generated using `fwt.generateKeys()`.
    - `keys.privateKey` - [`string`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Data_structures#String_type) Private key generated using `fwt.generateKeys()`.
  - Returns: [`Promise<token>`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise)
```js
fwt.generateToken({ foo: 'bar' }, 'secret', 300000, {
  publicKey: customPublicKey,
  privateKey: customPrivateKey
}) // Token will be valid for 5 minutes
  .then(token => console.log(token))
  .catch(err => console.log(err));
```

### generateTokenSync(payload, secret, expireTime[, keys])
This is used to generate a token synchronously. It returns the token as a string.
> Note: expireTime represents how many milliseconds the token should be valid.
  - payload - [`Object`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Working_with_Objects)
  - secret - [`string`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Data_structures#String_type)
  - expireTime - [`number`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Data_structures#Number_type)
  - keys - **Optional** - [`Object`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Working_with_Objects)
    - `keys.publicKey` - [`string`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Data_structures#String_type) Public key generated using `fwt.generateKeys()`.
    - `keys.privateKey` - [`string`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Data_structures#String_type) Private key generated using `fwt.generateKeys()`.
  - Returns: [`string`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Data_structures#String_type) Token
```js
const token = fwt.generateTokenSync({ foo: 'bar' }, 'secret', 300000, {
  publicKey: customPublicKey,
  privateKey: customPrivateKey
});
```

### verifyToken(token, secret[, keys])
This is used to verify a token's authenticity. It checks that the token is not expired, that the secret is the same as the one used to generate the token, and that the payload is an Object. It returns a Promise with the token payload.
  - token - [`string`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Data_structures#String_type)
  - secret - [`string`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Data_structures#String_type)
  - keys - **Optional** - [`Object`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Working_with_Objects)
    - `keys.publicKey` - [`string`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Data_structures#String_type) Public key generated using `fwt.generateKeys()`.
    - `keys.privateKey` - [`string`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Data_structures#String_type) Private key generated using `fwt.generateKeys()`.
  - Returns: [`Promise<tokenPayload>`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise)
```js
fwt.verifytoken(token, 'secret', {
  publicKey: customPublicKey,
  privateKey: customPrivateKey
})
  .then(payload => console.log(payload))
  .catch(err => console.log(err));
```

### verifyTokenSync(token, secret[, keys])
This is used to verify a token's authenticity. It checks that the token is not expired, that the secret is the same as the one used to generate the token, and that the payload is an Object. It returns a Boolean.
  - token - [`string`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Data_structures#String_type)
  - secret - [`string`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Data_structures#String_type)
  - keys - **Optional** - [`Object`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Working_with_Objects)
    - `keys.publicKey` - [`string`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Data_structures#String_type) Public key generated using `fwt.generateKeys()`.
    - `keys.privateKey` - [`string`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Data_structures#String_type) Private key generated using `fwt.generateKeys()`.
  - Returns: [`boolean`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Data_structures#Boolean_type) Returns `true` if token is valid. Otherwise `false` is returned.
```js
const token = fwt.generateTokenSync({ foo: 'bar' }, 'secret', 300000); // Generate token with default key modulus length.
const isValid = fwt.verifyTokenSync(token, 'secret'); // Returns true
```

### decodeToken(token[, keys])
This is used to decode a token's payload. It returns a Promise with the payload as an Object.
> Note that this does not check if a token's signature is valid or if the token has expired or not.
  - token - [`string`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Data_structures#String_type)
  - keys - **Optional** - [`Object`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Working_with_Objects)
    - `keys.privateKey` - [`string`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Data_structures#String_type) Private key generated using `fwt.generateKeys()`. Only the private key is needed to decode a token's payload.
  - Returns: [`Promise<tokenPayload>`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise)
```js
fwt.decodeToken(token, { privateKey: customPrivateKey })
  .then(payload => console.log(payload))
  .catch(err => console.log(err));
```

### decodeTokenSync(token[, keys])
This is used to decode a token's payload synchronously. It returns the decoded payload as an Object.
> Note that this does not check if a token's signature is valid or if the token has expired or not.
  - token - [`string`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Data_structures#String_type)
  - keys - **Optional** - [`Object`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Working_with_Objects)
    - `keys.privateKey` - [`string`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Data_structures#String_type) Private key generated using `fwt.generateKeys()`. Only the private key is needed to decode a token's payload.
  - Returns: [`Object`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Working_with_Objects) The decoded token payload.
```js
const payload = fwt.decodeTokenSync(token, { privateKey: customPrivateKey });
console.log(payload);
```

### generateKeys(modulusLength)
This is used to generate a key pair to use when generating, verifying, and decoding a token.
> Note that any token generated with a custom key pair must also be verified and decoded using that same key pair.
  - modulusLength - [`number`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Data_structures#Number_type)
  - Returns: 
    - `publicKey` - [`string`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Data_structures#String_type)
    - `privateKey` - [`string`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Data_structures#String_type)
```js
// ES6
const { publicKey, privateKey } = fwt.generateKeys(2048); // 2048 is the default length. If no key is provided to the other functions this one is used.
console.log(publicKey, privateKey);
// CommonJS
const keys = fwt.generateKeys(2048);
console.log(keys.publicKey, keys.privateKey);
```

## What's with the name?
This project is a reimplementation of JWT's. **It is not a way to fake JWT's for any malicious purpose!**
