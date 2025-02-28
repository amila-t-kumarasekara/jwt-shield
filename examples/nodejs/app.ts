import express from 'express';
import { authenticateToken, login, getProtectedData } from './auth';

const app = express();

app.use(express.json());

// Public routes
app.post('/login', login);

// Protected routes
app.get('/protected', authenticateToken, getProtectedData);

app.listen(3000, () => {
  console.log('Server running on port 3000');
}); 