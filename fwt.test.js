const fwt = require('./fwt');

// Custom keys for testing
const { publicKey, privateKey } = fwt.generateKeys(1024);
const testToken = fwt.generateTokenSync({ foo: 'bar' }, 'test', 300000);

describe('Test Promise based FWT with default keys', () => {
  it('Generates a token', () => {
    return fwt.generateToken({ foo: 'bar' }, 'test', 300000)
      .then(token => expect(typeof(token)).toBe('string'));
  });

  it('Verifies a token', () => {
    return fwt.verifyToken(testToken, 'test')
      .then(payload => expect(payload).toEqual({ foo: 'bar' }));
  });

  it('Decodes a token', () => {
    return fwt.decodeToken(testToken)
      .then(payload => expect(payload).toEqual({ foo: 'bar' }));
  });
});

describe('Test synchronous FWT with default keys', () => {
  it('Generates a token', () => {
    const genToken = fwt.generateTokenSync({ foo: 'bar' }, 'test', 300000);
    expect(typeof(genToken)).toBe('string');
  });

  it('Verifies a token', () => {
    const isValid = fwt.verifyTokenSync(testToken, 'test');
    expect(isValid).toBeTruthy();
  });

  it('Decodes a token', () => {
    const payload = fwt.decodeTokenSync(testToken);
    expect(payload).toEqual({ foo: 'bar' });
  });
});

describe('Test Promise based FWT with custom keys', () => {
  const customToken = fwt.generateTokenSync({ foo: 'bar' }, 'test', 300000, {
    publicKey: publicKey,
    privateKey: privateKey
  });
  it('Generates a token', () => {
    return fwt.generateToken({ foo: 'bar' }, 'test', 300000, {
      publicKey: publicKey,
      privateKey: privateKey
    })
      .then(token => expect(typeof(token)).toBe('string'));
  });

  it('Verifies a token', () => {
    return fwt.verifyToken(customToken, 'test', {
      publicKey: publicKey,
      privateKey: privateKey
    })
      .then(payload => expect(payload).toEqual({ foo: 'bar' }));
  });

  it('Decodes a token', () => {
    return fwt.decodeToken(customToken, {
      publicKey: publicKey,
      privateKey: privateKey
    })
      .then(payload => expect(payload).toEqual({ foo: 'bar' }));
  });
});

describe('Test synchronous FWT with custom keys', () => {
  const customToken = fwt.generateTokenSync({ foo: 'bar' }, 'test', 300000, {
    publicKey: publicKey,
    privateKey: privateKey
  });
  it('Generates a token', () => {
    const genToken = fwt.generateTokenSync({ foo: 'bar' }, 'test', 300000, {
      publicKey: publicKey,
      privateKey: privateKey
    });
    expect(typeof(genToken)).toBe('string');
  });

  it('Verifies a token', () => {
    const isValid = fwt.verifyTokenSync(customToken, 'test', {
      publicKey: publicKey,
      privateKey: privateKey
    });
    expect(isValid).toBeTruthy();
  });

  it('Decodes a token', () => {
    const payload = fwt.decodeTokenSync(customToken, {
      publicKey: publicKey,
      privateKey: privateKey
    });
    expect(payload).toEqual({ foo: 'bar' });
  });
});

describe('Test that Promise based verification finds an invalid token', () => {
  const invalidTokenSignature = fwt.generateTokenSync({ foo: 'bar' }, 'notTest', 300000);
  const invalidTokenTime = fwt.generateTokenSync({ foo: 'bar' }, 'test', 0);
  it('Detects an invalid signature', () => {
    expect.assertions(1);
    return fwt.verifyToken(invalidTokenSignature, 'test')
      .catch(err => {
        expect(err).toMatch('Invalid Token');
      });
  });

  it('Detects an invalid time', () => {
    expect.assertions(1);
    return fwt.verifyToken(invalidTokenTime, 'test')
      .catch(err => {
        expect(err).toMatch('Token has expired');
      });
  });
});

describe('Test that synchronous verification finds an invalid token', () => {
  const invalidTokenSignature = fwt.generateTokenSync({ foo: 'bar' }, 'notTest', 300000);
  const invalidTokenTime = fwt.generateTokenSync({ foo: 'bar' }, 'test', 0);
  it('Detects an invalid signature', () => {
    const isValid = fwt.verifyTokenSync(invalidTokenSignature, 'test');
    expect(isValid).toBeFalsy();
  });
  
  it('Detects an invalid time', () => {
    const isValid = fwt.verifyTokenSync(invalidTokenTime, 'test');
    expect(isValid).toBeFalsy();
  });
});

describe('Test that key generation works', () => {
  it('Generates two keys -- public and private', () => {
    const { publicKey, privateKey } = fwt.generateKeys(2048);
    expect(typeof(publicKey) && typeof(privateKey)).toBe('string');
  });
});
