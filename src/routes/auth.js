import { Router } from 'express';
import passport from 'passport';
import { UserValidation, LoginValidation } from '../validations';
import { verifyAuth, verifyLogin } from '../middlewares';
import authMiddleware from '../middlewares/token';
import UserController from '../controllers/user';
import { cacheToken, getToken } from '../helpers/token';
// import googleController from '../controllers/GoogleSocialController';
import facebookController from '../controllers/FacebookSocialController';
import models from '../database/models';
import { onSuccess } from '../controllers/GoogleSocialController';
import auth from '../controllers/auth';
import '../services/googlePassport';
import '../services/facebookPassport';

const { User } = models;

const { login, logout, generateToken } = auth;
const { verifyRefresh } = authMiddleware;

const router = Router();

router.post('/register', UserValidation.verifyUser, UserController.createUser);
router.get('/facebook', passport.authenticate('facebook', { scope: 'email' }));

router.get(
  '/auth/facebook/barefoot',
  passport.authenticate('facebook', { failureRedirect: '/failed' }),
  async function (req, res) {
    const { name, id, email, displayName } = req.user;
    const [newUser] = await User.findOrCreate({
      where: { facebookId: req.user.id },
      defaults: {
        firstName: name.familyName,
        lastName: name.givenName,
        userName: displayName,
        isVerified: true,
        facebookId: id,
      },
    });

    await newUser.update({ isVerified: true });

    const params = {
      user: { id: newUser.dataValues.id },
    };
    const duration = parseInt(process.env.TOKEN_EXPIRE, 10);
    const refreshDuration = parseInt(process.env.REFRESH_EXPIRE, 10);

    const accessTokenObject = getToken(params.user, duration);
    accessTokenObject.duration = duration;
    await cacheToken({ user: params.user, code: 'access' }, accessTokenObject);

    const refreshTokenObject = getToken(params.user, refreshDuration);
    refreshTokenObject.duration = refreshDuration;
    await cacheToken(
      { user: params.user, code: 'refresh' },
      refreshTokenObject
    );

    res.redirect(`${process.env.RIDIRECT}/?token=${accessTokenObject.token} `);
  }
);

router.get(
  '/google',
  passport.authenticate('google', { scope: ['email', 'profile'] })
);

router.get(
  '/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/failed' }),
  async function (req, res) {
    const { name, id, email, displayName } = req.user;
    const [newUser] = await User.findOrCreate({
      where: { email },
      defaults: {
        firstName: name.familyName,
        lastName: name.givenName,
        userName: displayName,
        googleId: id,
        isVerified: true,
        email,
      },
    });

    await newUser.update({ isVerified: true });

    const params = {
      user: { id: newUser.dataValues.id, email: newUser.dataValues.email },
    };
    const duration = parseInt(process.env.TOKEN_EXPIRE, 10);
    const refreshDuration = parseInt(process.env.REFRESH_EXPIRE, 10);

    const accessTokenObject = getToken(params.user, duration);
    accessTokenObject.duration = duration;
    await cacheToken({ user: params.user, code: 'access' }, accessTokenObject);
    console.log(accessTokenObject);

    res.redirect(`${process.env.RIDIRECT}/?token=${accessTokenObject.token} `);
  }
);

// router.get('/social/login', googleController.loginWithGoogle);

router.post('/login', LoginValidation.validateLogin, verifyLogin, login);
router.get('/logout', verifyAuth, logout);
router.post('/token', verifyAuth, verifyRefresh, generateToken);

export default router;
