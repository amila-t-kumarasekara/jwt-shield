import { SignOptions, Algorithm, VerifyOptions, JwtPayload } from 'jsonwebtoken';

export type SecureEncryptionAlgorithm = 
  | 'aes-256-gcm'
  | 'aes-256-cbc'
  | 'aes-192-gcm'
  | 'aes-192-cbc';

export interface SecureJWTOptions extends SignOptions {
  encryptionKey: string | Buffer;
  signingKey: string;
  algorithm?: Algorithm;
  encryptionAlgorithm?: SecureEncryptionAlgorithm;
  iterations?: number;
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
  keyId: string;
  authTag?: string;
}

export interface IJWTEncryptor {
  encrypt(data: string): EncryptionResult;
  decrypt(encryptedData: string, iv: string, authTag?: string): string;
}

export interface IJWTManager {
  sign(payload: JwtPayload): string;
  verify(token: string, verifyOptions: VerifyOptions): JwtPayload;
} 