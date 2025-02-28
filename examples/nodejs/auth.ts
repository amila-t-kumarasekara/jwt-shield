import { Router, Request, Response } from 'express';
import { JwtPayload } from 'jsonwebtoken';
import { SecureJWT } from 'jwt-shield';

const router = Router();

const jwtService = new SecureJWT({
  encryptionKey: process.env.JWT_SECRET ?? '7rtWJR/Izo9NDZWSWn0pHhcxv9YhjkFBOPMzWZqRYpQ=', //use 32 bytes for signing key
  signingKey: process.env.SIGNING_KEY ?? 'jwt-key',
  algorithm: 'HS256',
  encryptionAlgorithm: 'aes-256-gcm'
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
}

router.post('/login', async (req: Request, res: Response) => {
  try {
    const { username, password } = req.body;
    
    if (username === 'admin' && password === 'password') {
      console.log('signing payload', signInPayload);
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
    res.status(401).json({ valid: false, message: 'Invalid token' });
  }
});

export const authRouter = router; 