import jwt from 'jsonwebtoken';

const generateToken = async (res, userId) => {
  const token = jwt.sign({ id: userId }, process.env.JWT_SECRET, {
    expiresIn: '1d',
  });

  res.cookie('jwt', token, {
    httpOnly: true,
    sameSite: 'none',
    // sameSite: 'strict',
    maxAge: 30 * 24 * 60 * 60 * 1000,
  });
};

const tokenVerification = (req, res, next) => {
  const token = req.cookies.access_token;

  if (!token) return next(errorHandler(401, 'You need to login'));

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return next(errorHandler(403, 'Token is invalid'));
    req.user = user;
    next();
  });
};

export { generateToken, tokenVerification };
