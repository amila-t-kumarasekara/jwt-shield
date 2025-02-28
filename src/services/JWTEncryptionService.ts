import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';
import { 
  SecureEncryptionAlgorithm, 
  EncryptionResult, 
  GCMCipher, 
  GCMDecipher,
  IJWTEncryptor 
} from '../types';
import { SecureJWTError, SecureJWTErrorCode } from '../errors/SecureJWTError';

export class JWTEncryptionService implements IJWTEncryptor {
  constructor(
    private readonly encryptionKey: Buffer,
    private readonly encryptionAlgorithm: SecureEncryptionAlgorithm
  ) {}

  public encrypt(data: string): EncryptionResult {
    try {
      const iv = randomBytes(16);
      const cipher = createCipheriv(this.encryptionAlgorithm, this.encryptionKey, iv);
      
      let encrypted = cipher.update(data, 'utf8', 'base64');
      encrypted += cipher.final('base64');

      const authTag = this.encryptionAlgorithm.includes('gcm') 
        ? (cipher as unknown as GCMCipher).getAuthTag()
        : undefined;

      return {
        encryptedData: encrypted,
        iv: iv.toString('base64'),
        ...(authTag && { authTag: authTag.toString('base64') })
      };
    } catch (error) {
      throw new SecureJWTError(
        `Encryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        SecureJWTErrorCode.ENCRYPTION_FAILED,
        error instanceof Error ? error : undefined
      );
    }
  }

  public decrypt(encryptedData: string, iv: string, authTag?: string): string {
    try {
      if (this.encryptionAlgorithm.includes('gcm') && !authTag) {
        throw new SecureJWTError(
          'Authentication tag is required for GCM mode',
          SecureJWTErrorCode.MISSING_AUTH_TAG
        );
      }

      const decipher = createDecipheriv(
        this.encryptionAlgorithm,
        this.encryptionKey,
        Buffer.from(iv, 'base64')
      );

      if (this.encryptionAlgorithm.includes('gcm')) {
        (decipher as unknown as GCMDecipher).setAuthTag(Buffer.from(authTag!, 'base64'));
      }

      let decrypted = decipher.update(encryptedData, 'base64', 'utf8');
      decrypted += decipher.final('utf8');
      return decrypted;
    } catch (error) {
      if (error instanceof SecureJWTError) {
        throw error;
      }
      throw new SecureJWTError(
        `Decryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        SecureJWTErrorCode.DECRYPTION_FAILED,
        error instanceof Error ? error : undefined
      );
    }
  }
} 