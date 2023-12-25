import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
dotenv.config();

import session from 'express-session';
import passport from 'passport';
import passportGoogleStrategy from './passport.js';

import DBConfig from './config/DBConfig.js';
DBConfig;

import userRoutes from './routes/userRoutes.js';
import authRoutes from './routes/authRoutes.js';
import authRoute from './routes/authRoute.js';

const app = express();

app.use([express.json(), express.urlencoded({ extended: true })]);

app.use(
  session({
    secret: 'secret',
    resave: true,
    saveUninitialized: false,
    name: 'session',
    // cookie: { secure: true },
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000,
  })
);

// app.use(
//   cors({
//     origin: 'http://localhost:5173/',

//     // origin: [
//     //   'https://degeniusfx-frontend.onrender.com',
//     //   'http://localhost:5173/',
//     // ],
//     methods: 'GET, POST, PUT, DELETE',
//     credentials: true,
//   })
// );

app.use(
  cors(
    // {
    '*'
    // origin: process.env.BASE_URL,
    // origin: 'https://degeniusfx-frontend.onrender.com',
    // origin: 'http://localhost:5174',
    // methods: 'GET, POST, PUT, DELETE',
    // credentials: true,
    // }
  )
);

app.use(passport.initialize());
app.use(passport.session());

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

passportGoogleStrategy(passport);

app.use('/api/users', userRoutes);
app.use('/api/auth', authRoutes);
app.use('/auth', authRoute);

const port = process.env.PORT || 4045;

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
