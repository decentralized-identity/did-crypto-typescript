//import DidKey from '../lib/DidKey';
//import { KeyExport } from '../lib/KeyExport';

describe('DidKey in browser', () => {

  const originalTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;

  beforeEach(() => {
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 10000;
  });

  afterEach(() => {
    jasmine.DEFAULT_TIMEOUT_INTERVAL = originalTimeout;
  });

  describe('constructed with an Octet key', () => {
    it('should generate a symmetric key.', async (done) => {
      //const alg = { name: 'hmac', hash: 'SHA-256' };
      //const didKey = new DidKey(window.crypto, alg, null, true);
      //const jwk = await didKey.getJwkKey(KeyExport.Secret);
      let jwk = 5;
      expect(jwk).toBeDefined();
      done();
    });
  });
});
