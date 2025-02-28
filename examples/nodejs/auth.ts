import express from 'express';
import { SecureJWT, SecureJWTError, SecureJWTErrorCode } from 'secure-jwt';

const secureJwt = new SecureJWT({
  encryptionKey: process.env.JWT_ENCRYPTION_KEY!,
  signingKey: process.env.JWT_SIGNING_KEY!,
  expiresIn: '1d',
  encryptionAlgorithm: 'aes-256-gcm'
});

// Authentication middleware
export const authenticateToken = async (
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const user = await secureJwt.verify(token, {});
    req.user = user;
    next();
  } catch (error) {
    if (error instanceof SecureJWTError) {
      switch (error.code) {
        case SecureJWTErrorCode.INVALID_TOKEN:
          return res.status(401).json({ error: 'Invalid token' });
        case SecureJWTErrorCode.TOKEN_VERIFICATION_FAILED:
          return res.status(401).json({ error: 'Token verification failed' });
        default:
          return res.status(500).json({ error: 'Internal server error' });
      }
    }
    return res.status(500).json({ error: 'Internal server error' });
  }
};

// Login route
export const login = async (
  req: express.Request,
  res: express.Response
) => {
  const { username, password } = req.body;

  try {
    // Validate user credentials (example)
    const user = await validateUser(username, password);
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = secureJwt.sign({
      sub: user.id,
      username: user.username,
      role: user.role
    });

    res.json({ token });
  } catch (error) {
    if (error instanceof SecureJWTError) {
      return res.status(500).json({ error: 'Token generation failed' });
    }
    return res.status(500).json({ error: 'Internal server error' });
  }
};

// Protected route example
export const getProtectedData = async (
  req: express.Request,
  res: express.Response
) => {
  // req.user is set by the authenticateToken middleware
  res.json({
    message: 'Protected data',
    user: req.user
  });
}; 