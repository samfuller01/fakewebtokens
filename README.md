# fakewebtokens
A reimplementation of JSON Web Tokens. 

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
There are three functions that are exported by `fwt.js`. All of them return a Promise.

### generateToken(payload, secret, expireTime)
This is used to generate a token. It takes the passed in parameters and returns a Promise with the token.
  - payload - [`Object`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Working_with_Objects)
  - secret - [`string`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Data_structures#String_type)
  - expireTime - [`number`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Data_structures#Number_type) 
  - Returns: [`Promise<token>`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise)
  > Note: expireTime represents how many milliseconds the token should be valid.
```js
fwt.generateToken({ foo: 'bar' }, 'secret', 300000) // Token will be valid for 5 minutes
  .then(token => console.log(token))
  .catch(err => console.log(err));
```

### verifyToken(token, secret)
This is used to verify a token's authenticity. It checks that the token is not expired, that the secret is the same as the one used to generate the token, and that the payload is an Object.
  - token - [`string`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Data_structures#String_type)
  - secret - [`string`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Data_structures#String_type)
  - Returns: [`Promise<tokenPayload>`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise)
```js
fwt.verifytoken(token, 'secret')
  .then(payload => console.log(payload))
  .catch(err => console.log(err));
```

### decodeToken(token)
This is used to decode a token's payload. It returns a Promise with the payload as an Object.
> Note that this does not check if a token's signature is valid or if the token has expired or not.
  - token - [`string`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Data_structures#String_type)
  - Returns: [`Promise<tokenPayload>`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise)
```js
fwt.decodeToken(token)
  .then(payload => console.log(payload))
  .catch(err => console.log(err));
```

## What's with the name?
This project is a reimplementation of JWT's. **It is not a way to fake JWT's for any malicious purpose!**
