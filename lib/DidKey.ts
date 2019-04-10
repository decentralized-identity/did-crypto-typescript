
import base64url from 'base64url';
import { KeyExport } from './KeyExport';
import KeyObject from './KeyObject';
import { KeyOperation } from './KeyOperation';
import KeyTypeFactory, { KeyType } from './KeyType';
import KeyUseFactory, { KeyUse } from './KeyUse';
import MasterKey from './MasterKey';
import PairwiseKey from './PairwiseKey';
const clone = require('clone');

// Name curves
const CURVE_P256K = 'P-256K';
const CURVE_K256 = 'K-256';
const TEMPORARY_KID = '#key1';

/**
 * Class to model a key
 */
export default class DidKey {
  // key type
  private _keyType: KeyType;

  // key use
  private _keyUse: KeyUse;

  // algorithm to use
  private _algorithm: any;

  // the crypto object
  private _crypto: any;

  // Store symmetric key
  private _exportable: boolean;

  // Used to store the key passed by the caller
  private _rawKey: any;

  // Store for jwk keys in different formats. This is the format returned by exportKey
  private _jwkKeys: Map<string, object> = new Map<string, object>();

  // Set of master keys
  private _didMasterKeys: MasterKey[] = [];

  // Set of pairwise keys
  private _didPairwiseKeys: Map<string, DidKey> = new Map<string, DidKey>();

  /**
   * Create an instance of DidKey.
   * @param crypto The crypto object.
   * @param algorithm Intended algorithm to use for the key.
   * @param key The key.
   * @param exportable True if the key is exportable.
   */
  public constructor (crypto: any, algorithm: any, key: any = undefined, exportable: boolean = true) {
    this._crypto = crypto;

    // Check algorithm
    if (!algorithm.name) {
      throw new Error('Missing property name in algorithm');
    }

    this._keyUse = KeyUseFactory.create(algorithm);
    this._keyType = KeyTypeFactory.create(algorithm);
    this._exportable = exportable;
    this._algorithm = algorithm;

    // Set the raw key. Can be null if the key needs to be generated
    this._rawKey = key;
  }

  /**
   * Gets the intended algorithm to use for the key.
   */
  public get algorithm (): any {
    return this._algorithm;
  }

  /**
   * Gets the exportable property of the key indicating whether the app can extract the key.
   */
  public get exportable (): boolean {
    return this._exportable;
  }

  /**
   * Gets the key type.
   */
  public get keyType (): KeyType {
    return this._keyType;
  }

  /**
   * Gets the key use.
   */
  public get keyUse (): KeyUse {
    return this._keyUse;
  }

  /**
   * Gets the key in jwk format.
   */
  public async getJwkKey (keyExport: KeyExport): Promise<any> {
    // check if key is already cached
    const keyId = this.getKeyIdentifier(this.keyType, this.keyUse, keyExport);
    let jwkKey: any = this.getJwkKeyFromCache(keyId);
    if (jwkKey) {
      // Return the key if it already exists
      return jwkKey;
    }

    // Get the key or generate the key if needed
    jwkKey = await this.getOrGenerateKey(keyExport);

    // Normalize curve
    if (jwkKey.crv) {
      jwkKey.crv = this._algorithm.namedCurve;
    }

    // Save jwk format
    this.cacheJwkKey(keyId, jwkKey);

    // Check to save public key
    if (this.isKeyPair && keyExport === KeyExport.Private) {
      // Save only public key
      const jwkPublic: any = {};
      jwkPublic.kty = jwkKey.kty;

      if (jwkKey.use) {
        jwkPublic.use = jwkKey.use;
      }
      if (this.keyType === KeyType.RSA) {
        jwkPublic.e = jwkKey.e;
        jwkPublic.n = jwkKey.n;
      } else {
        jwkPublic.crv = this._algorithm.namedCurve;
        jwkPublic.x = jwkKey.x;
        jwkPublic.y = jwkKey.y;
      }

      // Save public key
      const keyIdPublic = this.getKeyIdentifier(this.keyType, this.keyUse, KeyExport.Public);
      this.cacheJwkKey(keyIdPublic, jwkPublic);
    }
    return jwkKey;
  }

  /**
   * Sign the data with the current key
   * @param data  Data to be signed with the current key
   */
  public async sign (data: Buffer): Promise<ArrayBuffer> {
    const keyExport = this.isKeyPair ? KeyExport.Private : KeyExport.Secret;
    let jwk = await this.getJwkKey(keyExport);
    jwk = DidKey.normalizeJwk(jwk);
    const operations = [KeyOperation.Sign];
    jwk.key_ops = operations;
    const alg = DidKey.normalizeAlgorithm(this._algorithm);
    const keyObject: any = await this._crypto.subtle.importKey(
      'jwk',
      jwk,
      alg,
      this._exportable,
     operations
    );

    const signature = await this._crypto.subtle.sign(alg, keyObject, data);
    return signature;
  }

  /**
   * Sign the data with the current key
   * @param data  The data signed with the current key
   * @param signature  The signature on the data
   */
  public async verify (data: Buffer, signature: ArrayBuffer): Promise<boolean> {
    // console.log(`Verify data: ${base64url(data)}`);
    const keyExport = this.isKeyPair ? KeyExport.Public : KeyExport.Secret;
    let jwk = await this.getJwkKey(keyExport);
    jwk = DidKey.normalizeJwk(jwk);
    const operations = [KeyOperation.Verify];
    jwk.key_ops = operations;
    const alg = DidKey.normalizeAlgorithm(this._algorithm);
    const keyObject: any = await this._crypto.subtle.importKey(
      'jwk',
      jwk,
      alg,
      this._exportable,
     operations
    );
    const success = await this._crypto.subtle.verify(alg, keyObject, signature, data);
    return success;
  }

  /**
   * Generate a pairwise key
   * @param seed  The master seed for generating pairwise keys
   * @param did  The owner DID
   * @param peerId  The representation of the peer
   */
  public async generatePairwise (seed: Buffer, did: string, peerId: string): Promise<DidKey> {
    let pairwiseDidKey: DidKey;
    const didMasterKey: MasterKey = await this.generateDidMasterKey(seed, did);
    const pairwise: DidKey | undefined = this._didPairwiseKeys.get(this.mapDidPairwiseKeys(did, peerId));
    if (pairwise) {
      return pairwise;
    }

    switch (this._keyType) {
      case KeyType.EC:
      case KeyType.RSA:
        // Generate new pairwise key
        const pairwiseKey: PairwiseKey = new PairwiseKey(did, peerId);
        pairwiseDidKey = await pairwiseKey.generate(
          didMasterKey.key,
          this._crypto,
          this._algorithm,
          this._keyType,
          this._keyUse,
          this._exportable
        );

        // Cache pairwise key
        this._didPairwiseKeys.set(this.mapDidPairwiseKeys(did, peerId), pairwiseDidKey);
        break;

      default:
        throw new Error(`Pairwise key for type '${this._keyType}' is not supported.`);
    }
    // Store private and public key.
    await pairwiseDidKey.getJwkKey(KeyExport.Private);
    return pairwiseDidKey;
  }

  /**
   * Normalize the algorithm so it can be used by underlying crypto.
   * @param algorithm Algorithm to be normalized
   */
  public static normalizeAlgorithm (algorithm: any) {
    if (algorithm.namedCurve) {
      if (algorithm.namedCurve === CURVE_P256K) {
        const alg = clone(algorithm);
        alg.namedCurve = CURVE_K256;
        return alg;
      }
    }

    return algorithm;
  }

  /**
   * Normalize the jwk so it can be used by underlying crypto.
   * @param jwk Json web key to be normalized
   */
  public static normalizeJwk (jwk: any) {
    if (jwk.crv) {
      if (jwk.crv === CURVE_P256K) {
        const key = clone(jwk);
        key.crv = CURVE_K256;
        return key;
      }
    }

    return jwk;
  }

  /**
   * Returns an array of key operations.
   */
  public getKeyOperations (keyUse: KeyUse, keyExport: KeyExport): Array<KeyOperation> {
    switch (keyUse) {
      case KeyUse.Encryption:
        if (this.isKeyPair) {
          return [KeyOperation.DeriveKey, KeyOperation.DeriveBits];
        }

        return [KeyOperation.Encrypt, KeyOperation.Decrypt];

      case KeyUse.Signature:
        if (keyExport === KeyExport.Secret || keyExport === KeyExport.Private) {
          return [KeyOperation.Sign];
        } else {
          return [KeyOperation.Verify];
        }
    }
  }

  /**
   * Returns a boolean indicating whether the key
   * type of the instance is either KeyType.EC or
   * KeyType.RSA.
   */
  private get isKeyPair (): boolean {
    return this._keyType === KeyType.EC || this._keyType === KeyType.RSA;
  }

  // Generate a unique key id for storage of pairwise keys
  private mapDidPairwiseKeys (did: string, peerId: string): string {
    // TODO add key use if we want different keys for signing and encryption
    return `${this._keyType}_${did}_${peerId}`;
  }

  /**
   * Generate a pairwise did master key.
   * @param seed  The master seed for generating pairwise keys
   * @param did  The owner DID
   * @param peerId  The representation of the peer
   */
  private async generateDidMasterKey (seed: Buffer, did: string): Promise<MasterKey> {
    let mk: MasterKey | undefined = undefined;

    // Check if key was already generated
    this._didMasterKeys.forEach(
      (masterKey: MasterKey): any => {
        if (masterKey.did === did) {
          mk = masterKey;
          return;
        }
      }
    );

    if (mk) {
      return mk;
    }

    const alg = { name: 'hmac', hash: 'SHA-512' };
    const signKey: DidKey = new DidKey(this._crypto, alg, seed);
    await signKey.getJwkKey(KeyExport.Secret);
    const signature: ArrayBuffer = await signKey.sign(Buffer.from(did));
    mk = new MasterKey(did, Buffer.from(signature));
    this._didMasterKeys.push(mk);
    return mk;
  }

  private getKeyIdentifier (keyType: KeyType, keyUse: KeyUse, keyExport: KeyExport): string {
    return `${keyType}-${keyUse}-${keyExport}`;
  }

  private getJwkKeyFromCache (keyId: string): object | undefined {
    // TODO add decryption with a system key
    return this._jwkKeys.get(keyId);
  }

  private cacheJwkKey (keyId: string, jwk: any): boolean {
    // TODO add encryption with a system key
    this._jwkKeys.set(keyId, jwk);
    return true;
  }

  // Get the key or generate the key if needed
  // Return a keyObject
  private async getOrGenerateKey (keyExport: KeyExport): Promise<any> {
    if (this._rawKey === null) {
      // indicate key is generated and raw key was not set by caller
      this._rawKey = undefined;

      // key generation required
      switch (this.keyType) {
        case KeyType.EC:
        case KeyType.RSA:
          return this.generateKeyPair(keyExport);
        case KeyType.Oct:
          return this.generateOctKey();
        default:
          throw new Error(`Key type '${this.keyType}' not supported`);
      }
    } else return this.setFromRawKey(this._rawKey, keyExport);
  }

  // Generate KeyObject from raw key
  private async setFromRawKey (key: any, keyExport: KeyExport): Promise<any> {
    if (!key) {
      throw new Error('Key must be defined');
    }

    let jwkKey = {};
    if (!key.kty) {
      jwkKey = {
        kty: 'oct',
        kid: TEMPORARY_KID,
        use: this.keyUse,
        k: base64url(key)
      };
    } else {
      if (!key.kid) {
        key.kid = TEMPORARY_KID;
      }
      jwkKey = key;
    }

    // cache the key
    const keyId = this.getKeyIdentifier(this.keyType, this.keyUse, keyExport);
    this.cacheJwkKey(keyId, jwkKey);
    return jwkKey;
  }

  // Generate an oct key and return a jwk key object
  private async generateOctKey (): Promise<any> {
    const keyObject: KeyObject = await this._crypto.subtle.generateKey(
      DidKey.normalizeAlgorithm(this._algorithm),
      this._exportable,
      this.getKeyOperations(this.keyUse, KeyExport.Secret)
    );

    const jwk = await this.keyObjectToJwk(keyObject, KeyExport.Secret);
    return jwk;
  }

  // Generate a key pair and return a key object
  private async generateKeyPair (keyExport: KeyExport): Promise<KeyObject> {
    const alg = DidKey.normalizeAlgorithm(this._algorithm);
    const operations = this.getKeyOperations(this.keyUse, keyExport);
    const keyObject: KeyObject = await this._crypto.subtle.generateKey(
      alg,
      this._exportable,
     operations);
    const jwk = await this.keyObjectToJwk(keyObject, keyExport);
    return jwk;
  }

  private async keyObjectToJwk (keyObject: KeyObject, keyExport: KeyExport) {
    let key = {};
    if (keyExport === KeyExport.Public) {
      key = keyObject.publicKey;
    } else if (keyExport === KeyExport.Private) {
      key = keyObject.privateKey;
    } else if (keyExport === KeyExport.Secret) {
      key = keyObject;
    }
    const jwk = await this._crypto.subtle.exportKey(
      'jwk',
      key);

    if (!jwk.kid) {
      jwk.kid = TEMPORARY_KID;
    }
    return jwk;
  }
}
