import DidKey from '../lib/DidKey';
import { KeyExport } from '../lib';
import SubtleCryptoElliptic from 'UserAgent-plugin-secp256k1';

const originalTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;
const crypto = new SubtleCryptoElliptic();

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
  { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([0x01, 0x00, 0x01]), hash: { name: 'SHA-256' } },
  { name: 'ECDSA', namedCurve: 'P-256K', hash: { name: 'SHA-256' } }
];

describe('DidKey in browser - RSA', () => {
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

  it('should sign/verify with a pairwise RSA key.', async (done) => {
    const alg = supportedAlgorithms[1];
    console.log(`Algorithm: ${JSON.stringify(alg)}`);
    const didKey = new DidKey(window.crypto, alg, null, true);
    expect(didKey).toBeDefined();
    const keyExport = KeyExport.Private;
    console.log(`Export: ${keyExport}`);

      // Generate pairwise
    const pairwise = await didKey.generatePairwise(Buffer.from('abcdefghijklmnopqrstuvwxyz'), 'did:ion:1234567890', 'did:ion:mypeer');
    console.log(pairwise);
    const pairwiseJwk = await pairwise.getJwkKey(keyExport);
    console.log(`Pairwise JWK: ${JSON.stringify(pairwiseJwk)}`);

      // Sign and verify
    const data = Buffer.from('abcdefg');
    const signature = await pairwise.sign(data);
    const success = await pairwise.verify(data, signature);
    console.log(`pairwise signature results: ${success}`);
    expect(success).toEqual(true);
    done();
  });

});
describe('DidKey in browser - secp256k1', () => {
  it('should sign/verify with an EC key.', async (done) => {
    const alg = supportedAlgorithms[2];
    console.log(`Algorithm: ${JSON.stringify(alg)}`);
    const didKey = new DidKey(crypto, alg, null, true);
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

  it('should sign/verify with a pairwise EC key.', async (done) => {
    const alg = supportedAlgorithms[2];
    console.log(`Algorithm: ${JSON.stringify(alg)}`);
    const didKey = new DidKey(crypto, alg, null, true);
    expect(didKey).toBeDefined();
    const keyExport = KeyExport.Private;
    console.log(`Export: ${keyExport}`);

      // Generate pairwise
    const pairwise = await didKey.generatePairwise(Buffer.from('abcdefghijklmnopqrstuvwxyz'), 'did:ion:1234567890', 'did:ion:mypeer');
    console.log(pairwise);
    const pairwiseJwk = await pairwise.getJwkKey(keyExport);
    console.log(`Pairwise JWK: ${JSON.stringify(pairwiseJwk)}`);

      // Sign and verify
    const data = Buffer.from('abcdefg');
    const signature = await pairwise.sign(data);
    const success = await pairwise.verify(data, signature);
    console.log(`pairwise signature results: ${success}`);
    expect(success).toEqual(true);
    done();
  });

});
