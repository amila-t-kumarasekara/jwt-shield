import express, { Request, Response, NextFunction } from 'express';
import { isSecureConnection } from 'jwt-shield/dist/utils/environment';
import { authRouter } from './auth';

const app = express();
app.use(express.json());

app.use((req: Request, res: Response, next: NextFunction) => {
  isSecureConnection(req);
  next();
});

app.use('/auth', authRouter);

app.get('/protected', (req: Request, res: Response) => {
  res.json({ message: 'This is a protected route!' });
});

const PORT = process.env.PORT ?? 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
}); 