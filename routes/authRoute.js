import express from 'express';
import passport from 'passport';
import User from '../models/userModels.js';
import { generateToken } from '../utils/verifyToken.js';
import dotenv from 'dotenv';
dotenv.config();

const router = express.Router();

router.get('/login/success', (req, res) => {
  if (req.user) {
    const { ...others } = req.user;

    res.status(200).json({
      message: 'Social media login successful',
      success: true,
      others,
      cookies: req.cookies,
    });
  }
});

router.get('/login/failed', (req, res) => {
  res.json({
    status: 401,
    success: false,
    message: 'failure',
  });
});

router.get(
  '/google',
  passport.authenticate('google', {
    scope: [
      'openid',
      'email',
      'profile',
      'https://www.googleapis.com/auth/userinfo.profile',
      'https://www.googleapis.com/auth/userinfo.email',
    ],
  })
);

router.get(
  '/google/callback',
  passport.authenticate('google', {
    // successRedirect: 'http://localhost:5174',
    successRedirect: `${process.env.BASE_URL}/user-dashboard`,
    failureRedirect: '/login/failed',
  })
);

export default router;
