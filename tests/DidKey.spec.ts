
import base64url from 'base64url';
import { Crypto } from '@peculiar/webcrypto';
import DidKey from '../lib/DidKey';
import { KeyExport } from '../lib/KeyExport';
import KeyObject from '../lib/KeyObject';
import { KeyType } from '../lib/KeyType';
import { KeyUse } from '../lib/KeyUse';
import { KeyOperation } from '../lib/KeyOperation';

class CryptoObject {
  /** Name of the crypto object */
  public name: string = '';

  /** Crypto object  */
  public crypto: any = null;
}

const webCryptoClass = new Crypto();

const crytoObjects: CryptoObject[] = [ { name: 'node-webcrypto-ossl', crypto: webCryptoClass } ];

const hmacAlgorithm = { name: 'hmac', hash: { name: 'SHA-256' } };
const sampleKey = '1234567890123456';

describe('DidKey', () => {

  let originalTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;

  beforeEach(() => {
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 10000;
  });

  afterEach(() => {
    jasmine.DEFAULT_TIMEOUT_INTERVAL = originalTimeout;
  });

  describe('utility tests', () => {
    it('should set the right properties for mapping jwa.', async (done) => {
      let alg = { name: 'hmac', hash: 'SHA-256' };
      let didKey: any = new DidKey(webCryptoClass, alg, Buffer.from(sampleKey), true);
      let jwk: any = await didKey.getJwkKey(KeyExport.Secret);
      expect(didKey.getJoseAlg(alg, jwk).alg).toEqual('hs256');

      alg = { name: 'hmac', hash: 'SHA-512' };
      didKey = new DidKey(webCryptoClass, alg, Buffer.from(sampleKey), true);
      jwk = await didKey.getJwkKey(KeyExport.Secret);
      expect(didKey.getJoseAlg(alg, jwk).alg).toEqual('hs512');

      alg = { name: 'hmac', hash: 'SHA-756' };
      didKey = new DidKey(webCryptoClass, alg, Buffer.from(sampleKey), true);
      jwk = await didKey.getJwkKey(KeyExport.Secret);
      let throws = false;
      try {
        didKey.getJoseAlg(alg, jwk);
      } catch (err) {
        expect(err.message).toEqual(`Algoritm ${JSON.stringify(alg)} is not supported`);
        throws = true;
      }
      expect(throws).toBe(true);

      alg = { name: 'rsassa-pkcs1-v1_5', hash: 'SHA-256' };
      didKey = new DidKey(webCryptoClass, alg, Buffer.from(sampleKey), true);
      jwk = await didKey.getJwkKey(KeyExport.Public);
      expect(didKey.getJoseAlg(alg, jwk).alg).toEqual('RS256');

      alg = { name: 'rsassa-pkcs1-v1_5', hash: 'SHA-512' };
      didKey = new DidKey(webCryptoClass, alg, Buffer.from(sampleKey), true);
      jwk = await didKey.getJwkKey(KeyExport.Public);
      expect(didKey.getJoseAlg(alg, jwk).alg).toEqual('RS512');

      alg = { name: 'rsassa-pkcs1-v1_5', hash: 'SHA-756' };
      didKey = new DidKey(webCryptoClass, alg, Buffer.from(sampleKey), true);
      jwk = await didKey.getJwkKey(KeyExport.Secret);
      throws = false;
      try {
        didKey.getJoseAlg(alg, jwk);
      } catch (err) {
        expect(err.message).toEqual(`Algoritm ${JSON.stringify(alg)} is not supported`);
        throws = true;
      }
      expect(throws).toBe(true);
      done();
    });
  });

  describe('constructed with an Octet key', () => {
    it('should set the right properties including symmetric key.', (done) => {
      crytoObjects.forEach(async (cryptoObj) => {
        const alg = { name: 'hmac', hash: 'SHA-256' };
        let didKey = new DidKey(cryptoObj.crypto, alg, Buffer.from(sampleKey), true);
        expect(KeyType.Oct).toEqual(didKey.keyType);
        expect(KeyUse.Signature).toEqual(didKey.keyUse);
        expect(alg).toEqual(didKey.algorithm);
        expect(true).toEqual(didKey.exportable);

        let key: any = await didKey.getJwkKey(KeyExport.Secret);
        expect(key).not.toBeNull();
        expect(key.kty).toBe('oct');
        expect(key.kid).toBeDefined();
        expect(base64url.encode(Buffer.from(sampleKey))).toBe(key.k);
      });
      done();
    });

    it('should generate a symmetric key.', (done) => {
      crytoObjects.forEach(async (cryptoObj) => {
        const alg = { name: 'hmac', hash: 'SHA-256' };
        let didKey = new DidKey(cryptoObj.crypto, alg, null, true);
        expect(KeyType.Oct).toEqual(didKey.keyType);
        expect(KeyUse.Signature).toEqual(didKey.keyUse);
        expect(alg).toEqual(didKey.algorithm);
        expect(true).toEqual(didKey.exportable);

        let key = await didKey.getJwkKey(KeyExport.Secret);
        expect(key).not.toBeNull();
        expect(key.kty).toBe('oct');
        expect(key.kid).toBeDefined();
        expect(key.k).not.toBeNull();
        expect(key.k).not.toBeUndefined();
      });
      done();
    });
    it('should set a symmetric key.', (done) => {
      crytoObjects.forEach(async (cryptoObj) => {
        const alg = { name: 'hmac', hash: 'SHA-256' };
        const jwk = {
          kty: 'oct',
          k: 'AABE',
          use: 'sig'
        };
        let didKey = new DidKey(cryptoObj.crypto, alg, jwk, true);
        expect(KeyType.Oct).toEqual(didKey.keyType);
        expect(KeyUse.Signature).toEqual(didKey.keyUse);
        expect(alg).toEqual(didKey.algorithm);
        expect(true).toEqual(didKey.exportable);

        let key = await didKey.getJwkKey(KeyExport.Secret);
        expect(key).not.toBeNull();
        expect(key.kty).toBe('oct');
        expect(key.kid).toBeDefined();
        expect(key.k).toEqual('AABE');
      });
      done();
    });

    it('should throw on unsupported algorithm ', () => {
      expect(() => new DidKey(webCryptoClass, { name: 'xxx' }, null)).toThrowError(`The algorithm 'xxx' is not supported`);
    });

    it('should throw on missing algorithm property', async (done) => {
      try {
        const didKey = new DidKey(webCryptoClass, { }, null, true);
        await didKey.getJwkKey(KeyExport.Secret);
        fail('Expected an exception');
      } catch (error) {
        expect(error.message).toBe('Missing property name in algorithm');
        done();
      }
    });

    it('should throw on missing key', async (done) => {
      try {
        const didKey = new DidKey(webCryptoClass, hmacAlgorithm, undefined, true);
        await didKey.getJwkKey(KeyExport.Secret);
        fail('Expected an exception');
      } catch (error) {
        expect(error.message).toBe('Key must be defined');
        done();
      }
    });

    it('should throw when key type not supported', async (done) => {
      try {
        const didKey = new DidKey(webCryptoClass, hmacAlgorithm, null, true);
        const did: any = didKey as any;
        did._keyType = 10;
        await didKey.getJwkKey(KeyExport.Secret);
        fail('Expected an exception');
      } catch (error) {
        expect(error.message).toBe(`Key type '10' not supported`);
        done();
      }
    });

    it('should create kid when not provided', async (done) => {
      const didKey = new DidKey(webCryptoClass, hmacAlgorithm, { kty: 'oct', k: 'AAEE' }, true);
      const did: any = didKey as any;
      did._keyType = 10;
      const jwk = await didKey.getJwkKey(KeyExport.Secret);
      expect(jwk.kid).toBeDefined();
      expect(jwk.kty).toEqual('oct');
      expect(jwk.k).toEqual('AAEE');

      done();
    });

    it('should create and verify a HMAC-SHA256 signature', async (done) => {
      let sampleKey = '1234567890';
      crytoObjects.forEach(async (cryptoObj) => {
        console.log(`Crypto object: ${cryptoObj.name}`);
        const alg = { name: 'hmac', hash: { name: 'SHA-256' } };
        const didKey = new DidKey(cryptoObj.crypto, alg, Buffer.from(sampleKey), true);

        const data = 'abcdefghij';

        // Make sure the key is set (promise is completed)
        const signature: ArrayBuffer = await didKey.sign(Buffer.from(data));
        const correct: boolean = await didKey.verify(Buffer.from(data), signature);
        expect(correct).toBeTruthy();
      });
      done();
    });

    it('should create and verify a HMAC-SHA512 signature', async (done) => {
      let sampleKey = '1234567890';
      crytoObjects.forEach(async (cryptoObj) => {
        console.log(`Crypto object: ${cryptoObj.name}`);
        const alg = { name: 'hmac', hash: { name: 'SHA-512' } };
        const didKey = new DidKey(cryptoObj.crypto, alg, Buffer.from(sampleKey), true);

        const data = 'abcdefghij';
        await didKey.getJwkKey(KeyExport.Secret);
        const signature: ArrayBuffer = await didKey.sign(Buffer.from(data));
        const correct: boolean = await didKey.verify(Buffer.from(data), signature);
        expect(correct).toBeTruthy();
      });
      done();
    });

    it('should return the correct key operations for a signature key', () => {
      crytoObjects.forEach(async (cryptoObj) => {
        const alg = { name: 'hmac', hash: 'SHA-256' };
        const didKey = new DidKey(cryptoObj.crypto, alg, Buffer.from(sampleKey), true);
        let operations: Array<KeyOperation> = didKey.getKeyOperations(KeyUse.Signature, KeyExport.Private);
        expect(operations).toEqual([ KeyOperation.Sign ]);
        operations = didKey.getKeyOperations(KeyUse.Signature, KeyExport.Public);
        expect(operations).toEqual([ KeyOperation.Verify ]);
      });
    });

    it('should return the correct key operations for a encryption key', () => {
      crytoObjects.forEach(async (cryptoObj) => {
        const alg = { name: 'hmac', hash: 'SHA-256' };
        const didKey = new DidKey(cryptoObj.crypto, alg, Buffer.from(sampleKey), true);
        const operations: Array<KeyOperation> = didKey.getKeyOperations(KeyUse.Encryption, KeyExport.Secret);
        expect(operations).toEqual([ KeyOperation.Encrypt, KeyOperation.Decrypt ]);
      });
    });
  });

  describe('constructed with an ECDSA key', () => {
    it('should set secp256k1 key', async (done) => {
      crytoObjects.forEach(async (cryptoObj) => {
        const alg = { name: 'ECDSA', namedCurve: 'P-256K', hash: { name: 'SHA-256' } };
        const didKey = new DidKey(cryptoObj.crypto, alg, null, true);
        const jwk = await didKey.getJwkKey(KeyExport.Private);
        jwk.use = 'sig';
        const importedKey = new DidKey(cryptoObj.crypto, alg, jwk, true);
        const importedJwk = await importedKey.getJwkKey(KeyExport.Private);
        expect(jwk.d).toEqual(importedJwk.d);
        expect(jwk.kty).toEqual(importedJwk.kty);
        expect('sig').toEqual(importedJwk.use);
      });
      done();
    });

    it('should sign and verify using a secp256k1 key', async (done) => {
      crytoObjects.forEach(async (cryptoObj) => {
        const alg = { name: 'ECDSA', namedCurve: 'P-256K', hash: { name: 'SHA-256' } };
        const didKey = new DidKey(cryptoObj.crypto, alg, null, true);

        const data = 'abcdefghij';
        const signature: ArrayBuffer = await didKey.sign(Buffer.from(data));
        const correct: boolean = await didKey.verify(Buffer.from(data), signature);
        expect(correct).toBeTruthy();
      });
      done();
    });

    it('should sign and verify with an imported secp256k1 key.', async (done) => {
      crytoObjects.forEach(async (cryptoObj) => {
        const alg = { name: 'ECDSA', namedCurve: 'P-256K', hash: { name: 'SHA-256' } };
        const generatedDidKey = new DidKey(cryptoObj.crypto, alg, null, true);
        let jwk = await generatedDidKey.getJwkKey(KeyExport.Private);
        let didKey = new DidKey(cryptoObj.crypto, alg, jwk, true);

        const data = 'abcdefghij';
        jwk = await didKey.getJwkKey(KeyExport.Private);
        expect(KeyType.EC).toBe(jwk.kty);
        const signature: ArrayBuffer = await didKey.sign(Buffer.from(data));

        // Make sure there is only the public key
        jwk.d = undefined;
        didKey = new DidKey(cryptoObj.crypto, alg, jwk, true);
        await didKey.getJwkKey(KeyExport.Public);
        const correct: boolean = await didKey.verify(Buffer.from(data), signature);
        expect(correct).toBeTruthy();
      });
      done();
    });

    it('should successfully import a secp256k1 key', async (done) => {
      crytoObjects.forEach(async (cryptoObj) => {
        const alg = { name: 'ECDSA', namedCurve: 'P-256K', hash: { name: 'SHA-256' } };

        // Generate the key pair
        const didKey = new DidKey(cryptoObj.crypto, alg, null, true);

        const ecKey1 = await didKey.getJwkKey(KeyExport.Private);
        expect(ecKey1).not.toBeNull();
        expect(ecKey1.kid).toBeDefined();
        expect(ecKey1.crv).toBe('P-256K');
        expect(ecKey1.kty).toBe('EC');
      });
      done();
    });

    it('should return the correct key operations for a EC encryption key', () => {
      crytoObjects.forEach(async (cryptoObj) => {
        const alg = { name: 'ECDSA', namedCurve: 'P-256K', hash: { name: 'SHA-256' } };
        const didKey = new DidKey(cryptoObj.crypto, alg, null, true);
        const operations: Array<KeyOperation> = didKey.getKeyOperations(KeyUse.Encryption, KeyExport.Private);
        expect(operations).toEqual([ KeyOperation.DeriveKey, KeyOperation.DeriveBits ]);
      });
    });
  });

  describe('constructed with an ECDH key', () => {
    it('should derive bits of for EC based Diffie-Hellman exchange', async (done) => {
      crytoObjects.forEach(async (cryptoObj) => {
        const alg: any = { name: 'ECDH', namedCurve: 'P-256K' };
        const normalizedAlgorithm = DidKey.normalizeAlgorithm(alg);
        const keyOperations = [ 'deriveKey', 'deriveBits' ];
        const privateKey = new DidKey(cryptoObj.crypto, alg, null, true);
        const privateKeyJwk = await privateKey.getJwkKey(KeyExport.Private);
        const importedPrivateKey = await cryptoObj.crypto.subtle
        .importKey('jwk', DidKey.normalizeJwk(privateKeyJwk), normalizedAlgorithm, true, keyOperations);

        const publicKey = new DidKey(cryptoObj.crypto, alg, null, true);
        const publicKeyJwk = await publicKey.getJwkKey(KeyExport.Public);
        const importedPublicKey = await cryptoObj.crypto.subtle
        .importKey('jwk', DidKey.normalizeJwk(publicKeyJwk), normalizedAlgorithm, true, keyOperations);

        const privateKeyObject = new KeyObject(KeyType.EC, importedPrivateKey);
        const publicKeyObject = new KeyObject(KeyType.EC, importedPublicKey);

        const bits: any = await cryptoObj.crypto.subtle.deriveBits({
          name: 'ECDH',
          public: publicKeyObject.publicKey
        }, privateKeyObject.privateKey, 128);
        expect(bits).toBeDefined();
        expect(bits.byteLength).toBe(16);
      });
      done();
    });
  });
});
