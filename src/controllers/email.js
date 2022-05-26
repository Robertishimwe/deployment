import EmailHelper from '../helpers/email';
import {
    confirmTemplate,
    resetPasswordTemplate,
} from '../helpers/email/templates';
import UserService from '../services/user.service';
import { cacheToken, getToken } from '../helpers/token';
import ErrorResponse from '../utils/errorResponse';
import { getTemplate } from '../helpers/email/config';

const { findUser } = UserService;

// initiate default email sender auth
const authClient = {
    clientId: process.env.GOOGLE_MAIL_CLIENT_ID,
    clientSecret: process.env.GOOGLE_MAIL_CLIENT_SECRET,
    redirectUri: process.env.GOOGLE_MAIL_REDIRECT_URI,
    refreshToken: process.env.GOOGLE_MAIL_REFRESH_TOKEN,
    email: process.env.EMAIL,
};

const duration = parseInt(process.env.EMAIL_TOKEN_EXPIRE, 10);

class EmailController {
    static send = async(email, token, template, senderAuth = authClient) => {
        const result = await EmailHelper.sendEmail(
            senderAuth,
            email,
            getTemplate(template)
        );

        if (result.envelope) {
            return { token };
        }
        return result;
    };

    static resendConfirmationEmail = async(req, res) => {
        try {
            const user = await findUser({ email: req.params.email });

            const userCode = {
                user: { id: user.id },
                code: 'verify',
            };

            const tokenObject = getToken({ id: user.id, email: user.email },
                duration
            );
            tokenObject.duration = duration;

            await cacheToken(userCode, tokenObject);

            const email = await this.send(
                user.email,
                tokenObject.token,
                confirmTemplate(
                    `${process.env.HOST}/api/users/verify/${tokenObject.token}`
                )
            );

            if (!email.token) {
                return ErrorResponse.badGatewayError(res, email.message);
            }
            res.json({ message: 'Confirm email', token: email.token });
        } catch (error) {
            if (error.message === 'User not found') {
                return ErrorResponse.notFoundError(res, error.message);
            }
            return ErrorResponse.internalServerError(res, error.message);
        }
    };

    static sendResetPasswordEmail = async(req, res) => {
        try {
            const user = await findUser({ email: req.body.email });

            const userCode = {
                user: { id: user.id },
                code: 'reset',
            };

            const tokenObject = getToken({ id: user.id, email: req.body.email },
                duration
            );
            tokenObject.duration = duration;

            await cacheToken(userCode, tokenObject);

            const email = await this.send(
                user.email,
                tokenObject.token,
                resetPasswordTemplate(
                    `${process.env.FONTENDHOST}/reset-password/?token=${tokenObject.token}`
                )
            );

            if (!email.token) {
                return ErrorResponse.badGatewayError(res, email.message);
            }
            res.json({ message: 'Reset password email', token: email.token });
        } catch (error) {
            if (error.message === 'User not found') {
                return ErrorResponse.notFoundError(res, 'User not found');
            }
            return res.status(502).json({ error: error.message });
        }
    };
}

export default EmailController;