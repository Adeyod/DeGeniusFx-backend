import jwt from 'jsonwebtoken';

// generate access token
const generateToken = async (res, userId) => {
  try {
    const token = jwt.sign({ id: userId }, process.env.JWT_SECRET, {
      expiresIn: '3600s',
    });

    res.cookie('jwt', token, {
      httpOnly: true,
      // sameSite: 'none',
      // sameSite: 'strict',
      maxAge: 1 * 60 * 60 * 1000,
    });
  } catch (error) {
    console.log(error);
    return;
  }
};

// verify access token
const tokenVerification = async (req, res, next) => {
  try {
    const token = req.cookies.access_token;

    if (!token) return next(errorHandler(401, 'You need to login'));

    await jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) return next(errorHandler(403, 'Token is invalid'));
      req.user = user;
      next();
    });
  } catch (error) {
    console.log(error);
    return;
  }
};

export { generateToken, tokenVerification };
