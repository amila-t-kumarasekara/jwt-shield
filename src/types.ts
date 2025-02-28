import { SignOptions, Algorithm, VerifyOptions } from 'jsonwebtoken';

export type SecureEncryptionAlgorithm = 
  | 'aes-256-gcm'
  | 'aes-256-cbc'
  | 'aes-192-gcm'
  | 'aes-192-cbc';

export interface SecureJWTOptions extends SignOptions {
  encryptionKey: string;
  signingKey: string;
  algorithm?: Algorithm;
  encryptionAlgorithm?: SecureEncryptionAlgorithm;
}

export interface JWTPayload {
  [key: string]: any;
  exp?: number;
  iat?: number;
  jti?: string;
}

export interface GCMCipher {
  getAuthTag(): Buffer;
}

export interface GCMDecipher {
  setAuthTag(buffer: Buffer): void;
}

export interface EncryptionResult {
  encryptedData: string;
  iv: string;
  authTag?: string;
}

export interface IJWTEncryptor {
  encrypt(data: string): EncryptionResult;
  decrypt(encryptedData: string, iv: string, authTag?: string): string;
}

export interface IJWTManager {
  sign(payload: JWTPayload): string;
  verify(token: string, verifyOptions: VerifyOptions): JWTPayload;
} 