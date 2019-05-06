![DIF Logo](https://raw.githubusercontent.com/decentralized-identity/decentralized-identity.github.io/master/images/logo-small.png)

# DID TypeScript Crypto

This library provides core crypto functions.  

## Deterministic Pairwise Keys
A core capability of this library is the generation of deterministic pairwise keys.  
A pairwise key is a unique key for a relationship between a persona (user's DID) and a peer such as a relying party or another DID user.  
Deterministic means that all pairwise keys can be recalculated. 

## Cryptography in Browser and Nodejs
Different environments such as a browser or Node.js support different crypto libraries.  
This library expects a crypto object which is the cryptography layer for the environment.
### Browser
```
window.crypto
```
### Node.js
```
import WebCrypto from 'node-webcrypto-ossl';
const crypto = new WebCrypto();
```


## Supported algorithms

The library supports RSA and elliptic curve secp256k1 keys.  
The library also supports secrets used for HMAC.  
The algorithm specification are conform with the [Web Cryptography API](https://www.w3.org/TR/WebCryptoAPI/).  
This [repo](https://github.com/diafygi/webcrypto-examples) has a collection of examples how to use the [Web Cryptography API](https://www.w3.org/TR/WebCryptoAPI/).   

### Key generation


 const didKey = new DidKey(crypto, algorithm, null, true);
  
  **crypto**: see [cryptography](#cryptography-in-browser-and-nodejs) section  
  **algorithm**: The generatekey algorithm as specified in [Web Cryptography API](https://www.w3.org/TR/WebCryptoAPI/)  
  **key**: null means that Didkey has to generate the key  
  **exportable**: True if the key can be exported 
  
Examples of supported algorithms  
* const algorithm = { name: 'hmac', hash: { name: 'SHA-256' } };
* const algorithm = { name: 'ECDSA', namedCurve: 'P-256K', hash: { name: 'SHA-256' } };
* const algorithm = { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([0x01, 0x00, 0x01]), hash: { name: 'SHA-256' } };


### methods of Didkey
const didKey = new DidKey(crypto, algorithm, null, true);  


#### Generate a pairwise key
const pairwiseKey: DidKey = await didKey.generatePairwise(seed, personaId, peerId);  
 **seed**: Buffer representing at least 32 bytes of random data  
 **personaId**: String representing an identifier for a persona (user's DID)  
 **peerId**: String representing an identifier for the peer  
 Remark: To generate a deterministic key for a persona, use the same value for personaId and peerId. 

#### Get the private key in Json Web Key format
const jwkKey = await didKey.getJwkKey(KeyExport.Private);
#### Get the public key in Json Web Key format
const jwkKey = await didKey.getJwkKey(KeyExport.Public);  


 




## Installation

Install the library into your project with npm:

```
npm install @decentralized-identity/did-crypto-typescript
```

## Crypto Dependancy

This library uses @peculiar/webcrypto as base crypto library for nodejs. This library is still in an experimental stage and should for now not be used in production code.
In the browser one can use the native window.crypto object supported in all modern browsers.

## Supported algorithms
The library supports the following algorithms for generating pairwise keys:
RSA
secp256k1
