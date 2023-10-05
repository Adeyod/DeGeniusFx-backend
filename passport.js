import passport from 'passport';
import bcrypt from 'bcryptjs';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import dotenv from 'dotenv';
// import crypto from 'crypto';
import User from './models/userModels.js';
import { generateToken } from './utils/verifyToken.js';
import { profile } from 'console';

dotenv.config();

passport.serializeUser((user, done) => {
  done(null, user);
});
passport.deserializeUser((user, done) => {
  const { password, ...others } = user;
  done(null, others);
});

const passportGoogleStrategy = (passport) => {
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: '/auth/google/callback',
      },
      async function (accessToken, refreshToken, profile, done) {
        let user = await User.findOne({ providerId: profile.id });
        if (user) {
          done(null, user);
        } else {
          const generatedPassword =
            profile.name.familyName +
            profile.name.givenName +
            Math.random().toString(32).slice(-8);

          const hashedPassword = bcrypt.hashSync(generatedPassword, 10);
          user = await new User({
            firstName: profile.name.givenName,
            lastName: profile.name.familyName,
            email: profile.emails[0].value,
            password: hashedPassword,
            // profilePicture: profile.photos[0].value,
            provider: profile.provider,
            providerId: profile.id,
            verified: true,
          });
          await user.save();
          done(null, user);
        }
      }
    )
  );
};

export default passportGoogleStrategy;
