import passport from 'passport';
import models from '../database/models';
import { cacheToken, getToken } from '../helpers/token';
import '../services/googlePassport';
import successResponse from '../utils/successResponse';

const { User } = models;
passport.use(passport.initialize());
passport.use(passport.session());

class googleController {
  static loginWithGoogle = async (req, res) => {
    res.render('login');
  };

  static onSuccess = async (req, res) => {
    try {
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
      console.log(newUser);

      const params = {
        user: {
          id: newUser.dataValues.id,
          email: newUser.dataValues.email,
          firstName: newUser.dataValues.firstName,
          lastName: newUser.dataValues.lastName,
          userName: newUser.dataValues.userName,
        },
      };
      console.log(params.user);
      const duration = parseInt(process.env.TOKEN_EXPIRE, 10);
      const refreshDuration = parseInt(process.env.REFRESH_EXPIRE, 10);

      const accessTokenObject = getToken(params.user, duration);
      accessTokenObject.duration = duration;
      await cacheToken(
        { user: params.user, code: 'access' },
        accessTokenObject
      );

      const refreshTokenObject = getToken(params.user, refreshDuration);
      refreshTokenObject.duration = refreshDuration;
      await cacheToken(
        { user: params.user, code: 'refresh' },
        refreshTokenObject
      );

      return successResponse(
        res.header('Authorization', `Bearer ${accessTokenObject.token}`),
        200,
        {
          message: 'logged in successfully',
          accessToken: accessTokenObject.token,
          refreshToken: refreshTokenObject.token,
        }
      );
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  };
}
export default googleController;
