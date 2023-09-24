import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
dotenv.config();

import DBConfig from './config/DBConfig.js';
DBConfig;

import userRoutes from './routes/userRoutes.js';
import authRoutes from './routes/authRoutes.js';

const app = express();

app.use([cors(), express.json(), express.urlencoded({ extended: true })]);

app.use('/api/users', userRoutes);
app.use('/api/auth', authRoutes);

// error middleware
app.use((err, req, res, next) => {
  const statusCode = err.statusCode || 500;
  const message = err.message || 'Internal Server Error';
  return res.json({
    success: false,
    message,
    statusCode,
  });
});

const port = process.env.PORT || 4045;

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
