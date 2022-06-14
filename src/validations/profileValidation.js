import Joi from 'joi';
import errorResponse from '../utils/errorResponse';

const profileCompleteSchema = Joi.object({
  dob: Joi.date().iso().less('12-31-2010').min('12-31-1800'),
  nationality: Joi.string(),
  gender: Joi.string().valid('male', 'female', 'prefer not say').required(),
  preferredLanguage: Joi.string().required(),
  preferredCurrency: Joi.string().required(),
  department: Joi.string().required(),
  address: Joi.string().required(),
  lineManager: Joi.string(),
  phoneNumber: Joi.string().required().required(),
  maritalStatus: Joi.string().valid('Single', 'Married', 'Widowed').required(),
});
const profileUpdateSchema = Joi.object({
  dob: Joi.date().iso().min('12-31-1850').max('12-31-2010'),
  nationality: Joi.string(),
  gender: Joi.string().valid('male', 'female', 'prefer not say'),
  preferredLanguage: Joi.string(),
  preferredCurrency: Joi.string(),
  department: Joi.string(),
  address: Joi.string(),
  lineManager: Joi.string(),
  phoneNumber: Joi.string(),
  maritalStatus: Joi.string().valid('Single', 'Married', 'Widowed'),
});

class profileValidation {
  static async validateComplete(req, res, next) {
    const { error } = profileCompleteSchema.validate(req.body);
    if (error) {
      return errorResponse.semanticError(
        res,
        `${error.message.replace(/["\\]/g, '')}`
      );
    }
    next();
  }

  static async validateUpdate(req, res, next) {
    const { error } = profileUpdateSchema.validate(req.body);
    if (error) {
      return errorResponse.semanticError(
        res,
        `${error.message.replace(/["\\]/g, '')}`
      );
    }
    next();
  }
}

export default profileValidation;
