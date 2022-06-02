import passport from 'passport';
import models from '../database/models';
import { cacheToken, getToken } from '../helpers/token';
import '../services/googlePassport';
import successResponse from '../utils/successResponse';

const { User } = models;
passport.use(passport.initialize());
passport.use(passport.session());

class facebookController {
  static onSuccessfb = async (req, res) => {
    try {
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
        user: {
          id: newUser.dataValues.id,
          firstName: newUser.dataValues.firstName,
          lastName: newUser.dataValues.lastName,
          userName: newUser.dataValues.userName,
        },
      };
      console.log(user);
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
        'logged in successfully',
        {
          accessToken: accessTokenObject.token,
          refreshToken: refreshTokenObject.token,
        }
      );
    } catch {
      res.status(500).send({ error: 'Oooops something went worng' });
    }
  };
}
export default facebookController;
