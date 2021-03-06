
import { KeyType } from './KeyType';

/**
 * Class to model an internal key object
 */
export default class KeyObject {
  // key type
  private _keyType: KeyType;

  // The public key
  private _publicKey: any;

  // The private key
  private _privateKey: any;

  // The key object. Can contain a symmetric key, key pair, private or public key
  private _keyObject: any;

  // Indicates whether the object contains a key pair
  private _isKeyPair: boolean;

  /**
   * Create an instance of DidKey.
   * @param keyType Key type.
   * @param keyObject The key object to store.
   */
  public constructor (keyType: KeyType, keyObject: any) {
    this._keyType = keyType;
    this._keyObject = keyObject;
    this._isKeyPair = false;

    if (this._keyObject.publicKey && this._keyObject.privateKey) {
      this._isKeyPair = true;
      this._publicKey = this._keyObject.publicKey;
      this._privateKey = this._keyObject.privateKey;
      return;
    } else {
      if (this._keyObject.type) {
        switch (this._keyObject.type) {
          case 'private':
            this._privateKey = this._keyObject;
            return;
          case 'public':
            this._publicKey = this._keyObject;
            return;
        }
      }

      throw new Error(`Key with type '${this._keyType}' is expected to have the type public or private`);
    }
  }

  /**
   * Gets the key type.
   */
  public get keyType (): KeyType {
    return this._keyType;
  }

  /**
   * Gets a value indicating whether the key is a public key crypto scheme
   */
  public get isPublicKeyCrypto (): boolean {
    return true;
  }

  /**
   * Gets a value indicating whether the key is a private key only
   */
  public get isPrivateKey (): boolean {
    if (this.isPublicKeyCrypto && this.privateKey) {
      return true;
    }

    return false;
  }

  /**
   * Gets a value indicating whether the key object is a key pair containing a public and private key
   */
  public get isKeyPair (): boolean {
    return this._isKeyPair;
  }

  /**
   * Gets public key
   */
  public get publicKey (): any {
    return this._publicKey;
  }

  /**
   * Gets private key
   */
  public get privateKey (): any {
    return this._privateKey;
  }
}
