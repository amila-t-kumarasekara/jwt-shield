import { createCipheriv, createDecipheriv, randomBytes, pbkdf2Sync, createHash } from 'crypto';
import { 
  SecureEncryptionAlgorithm, 
  EncryptionResult, 
  GCMCipher, 
  GCMDecipher,
  IJWTEncryptor 
} from '../types';
import { SecureJWTError, SecureJWTErrorCode } from '../errors/SecureJWTError';

export class JWTEncryptionService implements IJWTEncryptor {
  private readonly derivedKey: Buffer;
  private readonly keyId: string;

  constructor(
    private readonly encryptionKey: Buffer,
    private readonly encryptionAlgorithm: SecureEncryptionAlgorithm,
    private readonly iterations: number = 100000
  ) {
    this.validateKey(encryptionKey);
    this.derivedKey = this.deriveKey(encryptionKey);
    this.keyId = this.generateKeyId(encryptionKey);
  }

  private validateKey(key: Buffer): void {
    if (!Buffer.isBuffer(key)) {
      throw new SecureJWTError(
        'Encryption key must be a Buffer',
        SecureJWTErrorCode.INVALID_KEY
      );
    }

    const requiredKeyBytes = this.encryptionAlgorithm.startsWith('aes-256') ? 32 : 24;
    if (key.length < requiredKeyBytes) {
      throw new SecureJWTError(
        `Encryption key must be at least ${requiredKeyBytes} bytes for ${this.encryptionAlgorithm}`,
        SecureJWTErrorCode.INVALID_KEY_LENGTH
      );
    }

    const entropy = this.calculateEntropy(key);
    if (entropy < 3.5) { // Standard minimum entropy threshold
      throw new SecureJWTError(
        'Encryption key has insufficient entropy',
        SecureJWTErrorCode.INVALID_KEY
      );
    }
  }

  private deriveKey(key: Buffer): Buffer {
    try {
      const salt = createHash('sha256').update(key).digest('hex').slice(0, 16);
      return pbkdf2Sync(
        key,
        salt,
        this.iterations,
        this.encryptionAlgorithm.startsWith('aes-256') ? 32 : 24,
        'sha512'
      );
    } catch (error) {
      throw new SecureJWTError(
        'Key derivation failed',
        SecureJWTErrorCode.INVALID_KEY,
        error instanceof Error ? error : undefined
      );
    }
  }

  private generateKeyId(key: Buffer): string {
    return createHash('sha256')
      .update(key)
      .digest('hex')
      .slice(0, 8);
  }

  private calculateEntropy(buffer: Buffer): number {
    const frequencies = new Map<number, number>();
    for (const byte of buffer) {
      frequencies.set(byte, (frequencies.get(byte) || 0) + 1);
    }
    
    let entropy = 0;
    for (const count of frequencies.values()) {
      const probability = count / buffer.length;
      entropy -= probability * Math.log2(probability);
    }
    return entropy;
  }

  public encrypt(data: string): EncryptionResult {
    try {
      const iv = randomBytes(16);
      const cipher = createCipheriv(this.encryptionAlgorithm, this.derivedKey, iv);
      
      let encrypted = cipher.update(data, 'utf8', 'base64');
      encrypted += cipher.final('base64');

      const authTag = this.encryptionAlgorithm.includes('gcm') 
        ? (cipher as unknown as GCMCipher).getAuthTag()
        : undefined;

      return {
        encryptedData: encrypted,
        iv: iv.toString('base64'),
        keyId: this.keyId,
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
        this.derivedKey,
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