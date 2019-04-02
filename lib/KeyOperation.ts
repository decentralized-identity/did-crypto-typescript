/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * Enumeration for key operations
 */
export enum KeyOperation {
    Sign = 'sign',
    Verify = 'verify',
    Encrypt = 'encrypt',
    Decrypt = 'decrypt',
    WrapKey = 'wrapKey',
    UnwrapKey = 'unwrapKey',
    DeriveKey = 'deriveKey',
    DeriveBits = 'deriveBits'
}
