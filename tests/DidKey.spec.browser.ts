import DidKey from '../lib/DidKey';
import { KeyExport } from '../lib';

const originalTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;

beforeEach(() => {
  jasmine.DEFAULT_TIMEOUT_INTERVAL = 100000;
});

afterEach(() => {
  jasmine.DEFAULT_TIMEOUT_INTERVAL = originalTimeout;
});

afterAll(() => {
  console.log('Browser test finished');
});

const supportedAlgorithms = [
  { name: 'hmac', hash: 'SHA-256' },
  { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([0x01, 0x00, 0x01]), hash: { name: 'SHA-256' } }
];

describe('DidKey in browser', () => {
  it('should sign/verify with a symmetric key.', async (done) => {
    const alg = supportedAlgorithms[0];
    console.log(`Algorithm: ${JSON.stringify(alg)}`);
    const didKey = new DidKey(window.crypto, alg, null, true);
    expect(didKey).toBeDefined();
    console.log(didKey);
    const keyExport = KeyExport.Secret;
    console.log(`Export: ${keyExport}`);

      // Export jwk
    const jwk = await didKey.getJwkKey(keyExport);
    console.log(`JWK: ${JSON.stringify(jwk)}`);

      // Sign and verify
    const data = Buffer.from('abcdefg');
    console.log('before signature');
    const signature = await didKey.sign(data);
    console.log('after signature with signature: ' + signature);
    const success = await didKey.verify(data, signature);
    console.log(`signature results: ${success}`);
    expect(success).toEqual(true);
    done();
  });

  it('should sign/verify with an RSA key.', async (done) => {
    const alg = supportedAlgorithms[1];
    console.log(`Algorithm: ${JSON.stringify(alg)}`);
    const didKey = new DidKey(window.crypto, alg, null, true);
    expect(didKey).toBeDefined();
    console.log(didKey);
    const keyExport = KeyExport.Private;
    console.log(`Export: ${keyExport}`);

      // Export jwk
    const jwk = await didKey.getJwkKey(keyExport);
    console.log(`JWK: ${JSON.stringify(jwk)}`);

      // Sign and verify
    const data = Buffer.from('abcdefg');
    console.log('before signature');
    const signature = await didKey.sign(data);
    console.log('after signature with signature: ' + signature);
    const success = await didKey.verify(data, signature);
    console.log(`signature results: ${success}`);
    expect(success).toEqual(true);
    done();
  });
});
