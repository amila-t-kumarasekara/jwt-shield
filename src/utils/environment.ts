import { SecureJWTError, SecureJWTErrorCode } from '../errors/SecureJWTError';

export function isProduction(): boolean {
  return process.env.NODE_ENV === 'production';
}

export function isSecureConnection(req?: any): boolean {
  if (!isProduction()) {
    return true;
  }

  const isHttps = 
    process.env.HTTPS === 'true' || 
    process.env.SECURE_CONTEXT === 'true' ||
    process.env.NODE_ENV === 'production' && process.env.DYNO ||
    process.env.X_FORWARDED_PROTO === 'https' ||
    (req && (
      req.secure ||
      req.get('x-forwarded-proto') === 'https' ||
      req.protocol === 'https'
    ));

  return Boolean(isHttps);
}

export function validateSecureContext(req?: any): void {
  if (isProduction() && !isSecureConnection(req)) {
    throw new SecureJWTError(
      'HTTPS is required in production environment',
      SecureJWTErrorCode.INSECURE_CONTEXT
    );
  }
} 