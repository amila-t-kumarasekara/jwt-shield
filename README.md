# JWT Shield

A secure implementation of JSON Web Tokens (JWT) with encryption and signing capabilities. This package provides an extra layer of security by encrypting the JWT payload before signing, making it impossible to read the token contents without the proper encryption key.

## Features

- 🔒 **Double Security**: Combines encryption (AES) with JWT signing
- 🛡️ **GCM Support**: Uses AES-GCM by default for authenticated encryption
- 🔑 **Key Derivation**: Implements PBKDF2 for secure key derivation
- 🎯 **Type Safety**: Written in TypeScript with full type definitions
- ⚡ **Performance**: Optimized for minimal overhead
- 🔍 **Validation**: Built-in payload and key validation
- 🆔 **Key ID Support**: Includes key identification for key rotation

## Installation

```bash
npm install jwt-shield
# or
yarn add jwt-shield
```

## Quick Start

```typescript
import { SecureJWT } from 'jwt-shield';

// Initialize the service
const jwt = new SecureJWT({
  encryptionKey: process.env.JWT_ENCRYPTION_KEY,
  signingKey: process.env.JWT_SIGNING_KEY,
  algorithm: 'HS256',                // JWT signing algorithm
  encryptionAlgorithm: 'aes-256-gcm' // Encryption algorithm
});

// Sign a token
const token = jwt.sign({
  sub: 'user123',
  iss: 'https://your-domain.com',
  aud: 'https://your-domain.com',
  // ... other claims
});

// Verify a token
const payload = jwt.verify(token, {
  issuer: 'https://your-domain.com',
  audience: 'https://your-domain.com'
});
```

## Security Features

### 1. Payload Encryption
- The payload is encrypted using AES before JWT signing
- Supports AES-256-GCM and AES-256-CBC algorithms
- GCM mode provides authenticated encryption

### 2. Key Derivation
- Uses PBKDF2 with SHA-512 for key derivation
- Configurable iteration count (default: 100,000)
- Unique salt generation per key

### 3. Entropy Validation
- Validates encryption key entropy
- Prevents usage of weak keys
- Enforces minimum key length requirements

## Configuration Options

```typescript
interface SecureJWTOptions {
  encryptionKey: string | Buffer;    // Required: Key for payload encryption
  signingKey: string;               // Required: Key for JWT signing
  algorithm?: Algorithm;            // Optional: JWT signing algorithm (default: 'HS256')
  encryptionAlgorithm?: 'aes-256-gcm' | 'aes-256-cbc' | 'aes-192-gcm' | 'aes-192-cbc';
  iterations?: number;              // Optional: PBKDF2 iterations (default: 100000)
  expiresIn?: string | number;     // Optional: Token expiration (default: '1h')
}
```

## Key Generation

Generate secure keys for both encryption and signing:

```bash
# Generate encryption key (32 bytes, base64 encoded)
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"

# Generate signing key (32 bytes, base64 encoded)
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

Store these keys securely in your environment variables:

```env
JWT_ENCRYPTION_KEY=your_base64_encoded_32_byte_encryption_key
JWT_SIGNING_KEY=your_base64_encoded_signing_key
```

## Express.js Example

```typescript
import { SecureJWT } from 'jwt-shield';
import express from 'express';

const app = express();
const jwt = new SecureJWT({
  encryptionKey: process.env.JWT_ENCRYPTION_KEY,
  signingKey: process.env.JWT_SIGNING_KEY
});

app.post('/login', (req, res) => {
  const token = jwt.sign({
    sub: req.user.id,
    iss: 'https://api.example.com',
    aud: 'https://api.example.com'
  });
  res.json({ token });
});

app.post('/verify', (req, res) => {
  try {
    const payload = jwt.verify(req.body.token, {
      issuer: 'https://api.example.com',
      audience: 'https://api.example.com'
    });
    res.json({ valid: true, payload });
  } catch (error) {
    res.status(401).json({ valid: false });
  }
});
```

## Error Handling

The package throws `SecureJWTError` with specific error codes:

```typescript
enum SecureJWTErrorCode {
  INVALID_KEY = 'INVALID_KEY',
  INVALID_ALGORITHM = 'INVALID_ALGORITHM',
  ENCRYPTION_FAILED = 'ENCRYPTION_FAILED',
  DECRYPTION_FAILED = 'DECRYPTION_FAILED',
  MISSING_AUTH_TAG = 'MISSING_AUTH_TAG',
  INVALID_PAYLOAD = 'INVALID_PAYLOAD',
  TOKEN_VERIFICATION_FAILED = 'TOKEN_VERIFICATION_FAILED',
  INVALID_TOKEN = 'INVALID_TOKEN'
}
```

## Best Practices

1. **Key Management**:
   - Use different keys for development and production
   - Rotate keys periodically
   - Store keys securely (e.g., using a key management service)

2. **Token Claims**:
   - Always include `iss` (issuer) and `aud` (audience) claims
   - Set appropriate expiration times
   - Never include sensitive data like passwords

3. **Security**:
   - Use HTTPS for token transmission
   - Implement token revocation if needed
   - Consider using refresh tokens for long-lived sessions

## License

MIT

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting pull requests. 