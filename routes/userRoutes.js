import express from 'express';
const router = express.Router();

import { updateUser, getUserProfile } from '../controllers/userControllers.js';
import { protectedRoute } from '../middleware/authMiddleware.js';

router.post('/updateUser', updateUser);
router.get('/get', protectedRoute, getUserProfile);

export default router;
