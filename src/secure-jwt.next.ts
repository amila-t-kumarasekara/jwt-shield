import { SecureJWT } from './index';
import { SecureJWTOptions } from './types';

let secureJWTInstance: SecureJWT | null = null;

export const initSecureJWT = (options: SecureJWTOptions) => {
  secureJWTInstance = new SecureJWT(options);
  return secureJWTInstance;
};

export const getSecureJWT = () => {
  if (!secureJWTInstance) {
    throw new Error('SecureJWT not initialized. Call initSecureJWT first.');
  }
  return secureJWTInstance;
}; 