/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * enum to model key export types
 */
export enum KeyExport {
  /**
   * The secret key
   */
  Secret = 'secret',

  /**
   * The private part of a key pair
   */
  Private = 'private',

  /**
   * The public part of a key pair
   */
  Public = 'public'
}
