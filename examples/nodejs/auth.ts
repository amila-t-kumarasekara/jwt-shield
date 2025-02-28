import { Router, Request, Response } from 'express';
import { JwtPayload } from 'jsonwebtoken';
import { SecureJWT } from '../../dist/index';
import crypto from 'crypto';

const router = Router();

// Generate a 32-byte random key
const generateKey = () => crypto.randomBytes(32);

// Use environment variables or generate secure random keys
const encryptionKey = 'Ax3X5Gn54BHMDl0YAcI3yJz58mQzD0BMnSblydE2PCE='
const signingKey = 'Ax3X5Gn54BHMDl0YAcI3yJz58mQzD0BMnSblydE2PCE='

if (!process.env.JWT_ENCRYPTION_KEY) {
  console.warn(
    '[WARNING] Using a randomly generated encryption key. This is not recommended for production.\n' +
    'Tokens will become undecryptable when the server restarts.\n' +
    'Set JWT_ENCRYPTION_KEY environment variable for persistent tokens.'
  );
}

const jwtService = new SecureJWT({
  encryptionKey,
  signingKey,
  algorithm: 'HS256',
  encryptionAlgorithm: 'aes-256-gcm',
  expiresIn: '1h'
});

const signInPayload: JwtPayload = {
  username: 'admin',
  email: 'admin@example.com',
  role: 'admin',
  iss: 'https://example.com',
  sub: '1234567890',
  aud: 'https://example.com',
  exp: Math.floor(Date.now() / 1000) + (60 * 60), // 1 hour from now
  iat: Math.floor(Date.now() / 1000),
}

const verifyPayload = {
  issuer: 'https://example.com',
  audience: 'https://example.com',
  aud: 'https://example.com',
}

router.post('/login', async (req: Request, res: Response) => {
  try {
    const { username, password } = req.body;
    
    if (username === 'admin' && password === 'password') {
      const token = jwtService.sign(signInPayload);
      res.json({ token });
    } else {
      res.status(401).json({ message: 'Invalid credentials' });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error generating token' });
  }
});

router.post('/verify', async (req: Request, res: Response) => {
  try {
    const { token } = req.body;
    const payload = jwtService.verify(token, verifyPayload);
    res.json({ valid: true, payload });
  } catch (error) {
    console.error(error);
    res.status(401).json({ valid: false, message: 'Invalid token' });
  }
});

export const authRouter = router; 