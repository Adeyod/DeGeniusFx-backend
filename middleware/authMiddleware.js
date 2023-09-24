import jwt from 'jsonwebtoken';
import User from '../models/userModels.js';

const protectedRoute = async (req, res, next) => {
  const token = req.cookies.jwt;

  if (token) {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = await User.findById(decoded.userId).select('-password');
      next();
    } catch (error) {
      res.json({
        status: 401,
        message: 'Not authorized',
      });
    }
  } else {
    res.json({
      status: 402,
      message: 'Unauthorized',
    });
  }
};

export { protectedRoute };
