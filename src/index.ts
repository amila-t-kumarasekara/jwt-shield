import { randomBytes } from 'crypto';
import jwt, { JwtPayload } from 'jsonwebtoken';
import ms from 'ms/index';
import { 
  SecureJWTOptions, 
  IJWTManager,
} from './types';
import { JWTEncryptionService } from './services/JWTEncryptionService';
import { SecureJWTError, SecureJWTErrorCode } from './errors/SecureJWTError';

export class SecureJWT implements IJWTManager {
  private readonly encryptionService: JWTEncryptionService;
  private readonly signingKey: string;
  private readonly jwtAlgorithm: jwt.Algorithm;
  private readonly expiresIn?: ms.StringValue | number;
  private readonly options: SecureJWTOptions;

  constructor(options: SecureJWTOptions) {
    if (!options.encryptionKey || !options.signingKey) {
      throw new SecureJWTError(
        'Both encryptionKey and signingKey are required',
        SecureJWTErrorCode.INVALID_KEY
      );
    }

    const requestedAlgorithm = options.encryptionAlgorithm ?? 'aes-256-gcm';
    
    this.options = options;
    this.signingKey = options.signingKey;
    this.jwtAlgorithm = options.algorithm ?? 'HS256';
    this.expiresIn = options.expiresIn ?? '1h';

    try {
      let keyBuffer: Buffer;
      
      if (Buffer.isBuffer(options.encryptionKey)) {
        keyBuffer = options.encryptionKey;
      } else if (typeof options.encryptionKey === 'string') {
        if (this.isBase64(options.encryptionKey)) {
          keyBuffer = Buffer.from(options.encryptionKey, 'base64');
        } else {
          keyBuffer = Buffer.from(options.encryptionKey, 'utf-8');
        }
      } else {
        throw new SecureJWTError(
          'Encryption key must be a string or Buffer',
          SecureJWTErrorCode.INVALID_KEY
        );
      }

      this.encryptionService = new JWTEncryptionService(
        keyBuffer,
        requestedAlgorithm,
        options.iterations ?? 100000
      );
    } catch (error) {
      if (error instanceof SecureJWTError) {
        throw error;
      }
      throw new SecureJWTError(
        'Failed to initialize encryption service',
        SecureJWTErrorCode.INVALID_KEY,
        error instanceof Error ? error : undefined
      );
    }
  }

  private isBase64(str: string): boolean {
    try {
      const decoded = Buffer.from(str, 'base64').toString('base64');
      return decoded === str;
    } catch {
      return false;
    }
  }

  private getJWTSigningOptions(): jwt.SignOptions {
    const {
      encryptionKey,
      signingKey,
      encryptionAlgorithm,
      iterations,
      ...jwtOptions
    } = this.options;

    return {
      ...jwtOptions,
      algorithm: this.jwtAlgorithm,
      expiresIn: this.expiresIn
    };
  }

  public sign(payload: JwtPayload): string {
    try {
      if (payload.password) {
        throw new SecureJWTError(
          'Password is not allowed in payload',
          SecureJWTErrorCode.INVALID_PAYLOAD
        );
      }

      if (!payload.iss) {
        throw new SecureJWTError(
          'iss must be in the payload',
          SecureJWTErrorCode.INVALID_PAYLOAD
        );
      }

      if (!payload.aud) {
        throw new SecureJWTError(
          'aud must be in the payload',
          SecureJWTErrorCode.INVALID_PAYLOAD
        );
      }

      const payloadWithJti = {
        ...payload,
        jti: randomBytes(16).toString('hex')
      };

      const { encryptedData, iv, keyId, authTag } = this.encryptionService.encrypt(
        JSON.stringify(payloadWithJti)
      );
      
      return jwt.sign(
        { data: encryptedData, iv, aud: payload.aud, iss: payload.iss, sub: payload.sub, iat: payload.iat, keyId, ...(authTag && { authTag }) },
        this.signingKey,
        this.getJWTSigningOptions()
      );
    } catch (error) {
      if (error instanceof SecureJWTError) {
        throw error;
      }
      throw new SecureJWTError(
        `Token signing failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        SecureJWTErrorCode.TOKEN_VERIFICATION_FAILED,
        error instanceof Error ? error : undefined
      );
    }
  }

  public verify(token: string, verifyOptions: jwt.VerifyOptions): JwtPayload {
    try {
      if (!verifyOptions.issuer) {
        throw new SecureJWTError(
          'iss must be in the payload',
          SecureJWTErrorCode.INVALID_PAYLOAD
        );
      }

      if (!verifyOptions.audience) {
        throw new SecureJWTError(
          'aud must be in the payload',
          SecureJWTErrorCode.INVALID_PAYLOAD
        );
      }

      console.log('[SecureJWT Debug] Verifying token with options:', {
        ...verifyOptions,
        signingKey: this.signingKey ? '(present)' : '(missing)',
        algorithm: this.jwtAlgorithm
      });
      
      const decoded = jwt.verify(token, this.signingKey, verifyOptions) as { 
        data: string; 
        iv: string;
        keyId: string;
        authTag?: string;
      };
      
      if (!decoded || typeof decoded !== 'object' || !decoded.data || !decoded.iv || !decoded.keyId) {
        throw new SecureJWTError(
          'Invalid token format',
          SecureJWTErrorCode.INVALID_TOKEN
        );
      }

      const decryptedPayload = this.encryptionService.decrypt(
        decoded.data, 
        decoded.iv,
        decoded.authTag
      );
      
      try {
        return JSON.parse(decryptedPayload);
      } catch (error) {
        throw new SecureJWTError(
          'Invalid payload format',
          SecureJWTErrorCode.INVALID_PAYLOAD,
          error instanceof Error ? error : undefined
        );
      }
    } catch (error) {
      if (error instanceof SecureJWTError) {
        throw error;
      }
      throw new SecureJWTError(
        `Token verification failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        SecureJWTErrorCode.TOKEN_VERIFICATION_FAILED,
        error instanceof Error ? error : undefined
      );
    }
  }
} 