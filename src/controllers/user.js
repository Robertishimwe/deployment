import UserService from '../services/user.service';
import redis from '../database/redis';
import ErrorResponse from '../utils/errorResponse';
import Protection from '../helpers/encryption';
import { cacheToken, getToken } from '../helpers/token';
import EmailController from './email';
import { confirmTemplate } from '../helpers/email/templates';
import models from '../database/models';
import {
  findAllUsers,
  changeRole,
  checkUserById,
} from '../services/role.service';

const { createUser, checkUser } = UserService;

const { Role } = models;

class UserController {
  static createUser = async (req, res) => {
    try {
      // check if a user is in the database
      const check = {
        email: req.body.email,
      };

      await checkUser(check);

      // Hash the Password
      const hashedPassword = Protection.hashPassword(req.body.password);

      const user = await createUser({
        firstName: req.body.firstName,
        lastName: req.body.lastName,
        email: req.body.email,
        userName: req.body.userName,
        password: hashedPassword,
      });

      // create and Assign a token
      const params = {
        user: { id: user.id, username: user.userName, email: user.email },
      };

      const duration = parseInt(process.env.TOKEN_EXPIRE, 10);
      const refreshDuration = parseInt(process.env.REFRESH_EXPIRE, 10);
      const emailDuration = parseInt(process.env.EMAIL_TOKEN_EXPIRE, 10);

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

      const emailTokenObject = getToken(params.user, emailDuration);
      emailTokenObject.duration = process.env.EMAIL_TOKEN_EXPIRE;
      await cacheToken({ user: params.user, code: 'verify' }, emailTokenObject);

      // Send a confirmation email
      const email = await EmailController.send(
        user.email,
        emailTokenObject.token,
        confirmTemplate(
          `https://code-ninjas-fe-git-ft-verification-page-codeninjas.vercel.app/api/users/verify/?token=${emailTokenObject.token}`
        )
      );

      res.header('Authorization', `Bearer ${accessTokenObject.token}`);
      res.status(200).json({
        message: 'User created successfully',
        accessToken: accessTokenObject.token,
        refreshToken: refreshTokenObject.token,
        email: { message: 'Confirm email', token: email.token },
      });
    } catch (error) {
      if (error.message === 'Found') {
        return res.status(409).json({ error: 'email already exists' });
      }
      res.status(500).json({ error: error.message });
    }
  };

  static verifyUser = async (req, res) => {
    try {
      const { user } = req;

      await user.update({ isVerified: true });

      // Destroy the token afterwards by removing from cache
      await redis.keys(`*${user.id}-verify*`, (error, result) => {
        if (error) return error;

        const pipeline = redis.pipeline();
        result.forEach((key) => pipeline.del(key));

        return pipeline.exec((err, res) => {
          if (err) return err;
          return res;
        });
      });

      return res.json({ message: 'Email verified!' });
    } catch (error) {
      return ErrorResponse.internalServerError(res, error.message);
    }
  };

  static inputNewPassword = async (req, res) => {
    try {
      return res.json({ message: 'Ready for new password input' });
    } catch (error) {
      return ErrorResponse.internalServerError(res, error.message);
    }
  };

  static setNewPassword = async (req, res) => {
    try {
      const { user, tokenId } = req;
      const password = Protection.hashPassword(req.body.password);
      await user.update({ password });

      // Destroy the token afterwards by removing from cache
      await redis.del(
        `${process.env.NODE_ENV}:user-${user.id}-reset-${tokenId}`
      );

      res.json({ message: 'Password modified successfully!' });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  };

  static getAllUsers = async (req, res) => {
    try {
      const users = await findAllUsers();
      res.status(200).json(users);
    } catch (error) {
      res.status(400).json({ message: error.message });
    }
  };

  static assignRoles = async (req, res) => {
    const userRole = req.body.RoleId;
    const userId = req.params.id;
    const userExist = await checkUserById(userId, Role);

    if (!userExist) {
      return res.status(404).json({ message: 'User does not exist' });
    }

    try {
      await changeRole(userRole, userId).then(
        res.status(200).json({ message: 'User Role updated successfully' })
      );
    } catch (error) {
      res.status(500).json({ message: 'Error updating role' });
    }
  };
}

export default UserController;
