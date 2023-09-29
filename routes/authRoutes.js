import express from 'express';
import {
  register,
  authUser,
  verifyUser,
  userLogout,
  resetPassword,
  forgotPassword,
} from '../controllers/authControllers.js';
// import User from '../models/userModels.js';
// import Token from '../models/tokenModels.js';
const router = express.Router();

router.post('/register', register);
router.post('/', authUser);
router.get('/logout', userLogout);

router.get('/:id/confirm/:token', verifyUser);
router.post('/forgotPassword', forgotPassword);
router.post('/reset-password/:id/:token', resetPassword);

export default router;
