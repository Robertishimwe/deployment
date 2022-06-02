import redisClient from '../database/redis';
import successRes from '../utils/successResponse';
import ErrorResponse from '../utils/errorResponse';
import { cacheToken, getToken } from '../helpers/token';

const duration = parseInt(process.env.TOKEN_EXPIRE, 10);
const refreshDuration = parseInt(process.env.TOKEN_EXPIRE, 10);

class Auth {
  static async login(req, res, next) {
    try {
      const foundUser = req.user;

      const user = {
        id: foundUser.id,
        email: foundUser.email,
        roleId: foundUser.roleId,
        firstName: foundUser.firstName,
        lastName: foundUser.lastName,
        userName: foundUser.userName,
      };

      const accessTokenObject = getToken(user, duration);
      accessTokenObject.duration = duration;

      await cacheToken({ user, code: 'access' }, accessTokenObject);

      const refreshTokenObject = getToken(user, refreshDuration);
      refreshTokenObject.duration = refreshDuration;
      await cacheToken({ user, code: 'refresh' }, refreshTokenObject);

      return successRes(
        res.header('Authorization', `Bearer ${accessTokenObject.token}`),
        200,
        'User login successful :)',
        {
          accessToken: accessTokenObject.token,
          refreshToken: refreshTokenObject.token,
        }
      );
    } catch (err) {
      return ErrorResponse.internalServerError(res, err.message);
    }
  }

  static generateToken = async (req, res, next) => {
    try {
      const { id, email, userName, firstName, lastName } = req.user;
      const { tokenId, refreshTokenId } = req;
      const user = { id, email, userName, firstName, lastName };

      const accessTokenObject = getToken(user, duration, tokenId);
      accessTokenObject.duration = duration;
      await cacheToken({ user, code: 'access' }, accessTokenObject);

      const refreshTokenObject = getToken(
        user,
        refreshDuration,
        refreshTokenId
      );
      refreshTokenObject.duration = refreshDuration;
      await cacheToken({ user, code: 'refresh' }, refreshTokenObject);

      return successRes(
        res.header('Authorization', `Bearer ${accessTokenObject.token}`),
        200,
        'Token creation successful :)',
        {
          accessToken: accessTokenObject.token,
          refreshToken: refreshTokenObject.token,
        }
      );
    } catch (err) {
      return ErrorResponse.internalServerError(
        res,
        'Oops! Error while creating token'
      );
    }
  };

  static async logout(req, res, next) {
    try {
      const { tokenId, user } = req;

      await redisClient.del(
        `${process.env.NODE_ENV}:user-${user.id}-access-${tokenId}`
      );

      return successRes(res, 200, 'User logout successful');
    } catch (error) {
      return ErrorResponse.internalServerError(
        res,
        `Unable to log out user!! ${error.message}`
      );
    }
  }
}

export default Auth;
