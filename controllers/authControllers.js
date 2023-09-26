import User from '../models/userModels.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { errorHandler } from '../middleware/errorHandler.js';
import generateToken from '../utils/verifyToken.js';
import Token from '../models/tokenModels.js';
import crypto from 'crypto';
import sendEmail from '../utils/sendEmail.js';
import verifyMail from '../utils/sendEmail.js';

const register = async (req, res, next) => {
  const { firstName, lastName, email, password, address } = req.body;
  const verifyUser = await User.findOne({ email });
  if (verifyUser) {
    return next(errorHandler(404, 'User already exist'));
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await new User({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      // tel,
      address,
      // image,
    });
    let user = await newUser.save();

    // generate verification token
    const token = await new Token({
      userId: user._id,
      token: crypto.randomBytes(32).toString('hex'),
    });
    await token.save();

    // send mail
    const link = `${process.env.BASE_URL}users/${user._id}/confirm/${token.token}`;
    await verifyMail(user.email, link);
    res.json({
      status: 200,
      message: 'Email sent, check your mail...',
    });

    // res.json({
    //   status: 200,
    //   message: 'Registration Successful, Login...',
    // });
  } catch (error) {
    next(error);
    return;
  }
};

// FOR EMAIL VERIFICATION
const verifyUser = async (req, res) => {
  try {
    const user = await User.findOne({ _id: req.params.id });
    if (!user) {
      res.json({
        status: 400,
        message: 'Invalid Link',
      });
    }

    const token = await Token.findOne({
      userId: user._id,
      token: req.params.token,
    });

    if (!token) {
      res.json({
        status: 400,
        message: 'Invalid link',
      });
      return;
    }

    await User.updateOne({ _id: token.userId }, { $set: { verified: true } });
    await Token.findByIdAndRemove(token);
    res.json({
      message: 'email verified successfully, you can now login...',
      status: 200,
    });
  } catch (error) {
    res.json({
      status: 400,
      message: 'Email validation error',
    });
    return;
  }
};

const authUser = async (req, res, next) => {
  const { email, password } = req.body;
  try {
    const validUser = await User.findOne({ email });

    if (!validUser) {
      return next(errorHandler(404, 'Invalid user'));
    }
    const validPassword = await bcrypt.compare(password, validUser.password);
    if (!validPassword) {
      return next(errorHandler(404, 'Invalid user'));
    }

    if (validUser.verified === false) {
      let token = await Token.findOne({ userId: validUser._id });
      if (!token) {
        token = await new Token({
          userId: validUser._id,
          token: crypto.randomBytes(32).toString('hex'),
        });
        await token.save();

        const link = `${process.env.BASE_URL}users/${validUser._id}/confirm/${token.token}`;

        await sendEmail(validUser.email, link);
        res.json({
          status: 200,
          success: false,
          message: 'Verification email has been sent to your email',
        });
        return;
      }
      return res.json({
        status: 400,
        success: false,
        message: 'Email sent to your account, Verify',
      });
    }

    const { password: hashedPassword, ...others } = validUser._doc;

    generateToken(res, validUser._id);
    res.status(201).json({
      others,
      success: true,
      message: `${validUser.firstName} your login is successful`,
    });
    return;
  } catch (error) {
    next(errorHandler(400, 'Invalid Token'));
    return;
  }
};

const userLogout = async (req, res) => {
  res.clearCookie('jwt').json({
    message: 'Logout Successful',
    status: 200,
  });
};

export { register, authUser, userLogout, verifyUser };
