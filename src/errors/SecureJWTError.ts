export class SecureJWTError extends Error {
  constructor(
    message: string,
    public readonly code: SecureJWTErrorCode,
    public readonly originalError?: Error
  ) {
    super(message);
    this.name = 'SecureJWTError';
  }
}

export enum SecureJWTErrorCode {
  INVALID_KEY = 'INVALID_KEY',
  INVALID_ALGORITHM = 'INVALID_ALGORITHM',
  ENCRYPTION_FAILED = 'ENCRYPTION_FAILED',
  DECRYPTION_FAILED = 'DECRYPTION_FAILED',
  MISSING_AUTH_TAG = 'MISSING_AUTH_TAG',
  INVALID_PAYLOAD = 'INVALID_PAYLOAD',
  TOKEN_VERIFICATION_FAILED = 'TOKEN_VERIFICATION_FAILED',
  INVALID_TOKEN = 'INVALID_TOKEN',
  INSECURE_CONTEXT = 'INSECURE_CONTEXT'
} 