import { randomBytes } from 'crypto';
import jwt, { JwtPayload } from 'jsonwebtoken';
import { 
  SecureJWTOptions, 
  IJWTManager,
  SecureEncryptionAlgorithm 
} from './types';
import { JWTEncryptionService } from './services/JWTEncryptionService';
import { SecureJWTError, SecureJWTErrorCode } from './errors/SecureJWTError';

export class SecureJWT implements IJWTManager {
  private readonly encryptionService: JWTEncryptionService;
  private readonly signingKey: string;
  private readonly jwtAlgorithm: jwt.Algorithm;
  private readonly expiresIn?: string | number;
  private readonly options: SecureJWTOptions;

  constructor(options: SecureJWTOptions) {
    if (!options.encryptionKey || !options.signingKey) {
      throw new SecureJWTError(
        'Both encryptionKey and signingKey are required',
        SecureJWTErrorCode.INVALID_KEY
      );
    }

    const requestedAlgorithm = options.encryptionAlgorithm ?? 'aes-256-gcm';
    this.validateEncryptionKey(options.encryptionKey, requestedAlgorithm);

    this.options = options;
    this.signingKey = options.signingKey;
    this.jwtAlgorithm = options.algorithm ?? 'HS256';
    this.expiresIn = options.expiresIn ?? '1h';
    
    const keyBuffer = Buffer.from(options.encryptionKey, 'utf-8');
    this.encryptionService = new JWTEncryptionService(keyBuffer, requestedAlgorithm);
  }

  private validateEncryptionKey(key: string, algorithm: SecureEncryptionAlgorithm): void {
    try {
      const requiredKeyBytes = algorithm.startsWith('aes-256') ? 32 : 24;
      const keyBuffer = Buffer.from(key, 'utf-8');
      
      if (keyBuffer.length < requiredKeyBytes) {
        throw new SecureJWTError(
          `Encryption key must be at least ${requiredKeyBytes} bytes for ${algorithm}`,
          SecureJWTErrorCode.INVALID_KEY
        );
      }
    } catch (error) {
      if (error instanceof SecureJWTError) {
        throw error;
      }
      throw new SecureJWTError(
        'Invalid encryption key format',
        SecureJWTErrorCode.INVALID_KEY,
        error instanceof Error ? error : undefined
      );
    }
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

      const { encryptedData, iv } = this.encryptionService.encrypt(
        JSON.stringify(payloadWithJti)
      );
      
      return jwt.sign(
        { data: encryptedData, iv },
        this.signingKey,
        {
          ...this.options,
          algorithm: this.jwtAlgorithm,
          expiresIn: Number(this.expiresIn),
        }
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

      const decoded = jwt.verify(token, this.signingKey, verifyOptions) as { data: string; iv: string };
      
      if (!decoded || typeof decoded !== 'object' || !decoded.data || !decoded.iv) {
        throw new SecureJWTError(
          'Invalid token format',
          SecureJWTErrorCode.INVALID_TOKEN
        );
      }

      const decryptedPayload = this.encryptionService.decrypt(decoded.data, decoded.iv);
      
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