import bcrypt from 'bcrypt';
import { sign, verify } from 'jsonwebtoken';

const { TOKEN_SECRET, REFRESH_SECRET } = process.env;

class Protection {
  static async signToken(data, expire) {
    const token = sign(data, TOKEN_SECRET, { expiresIn: expire });
    return token;
  }

  static async signRefresh(data, expire) {
    const token = sign(data, REFRESH_SECRET, { expiresIn: expire });
    return token;
  }

  static async verifyToken(token) {
    const data = verify(token, TOKEN_SECRET);
    return data;
  }

  static async verifyRefresh(token) {
    const data = verify(token, REFRESH_SECRET);
    return data;
  }

  static hashPassword(password) {
    return bcrypt.hashSync(password, bcrypt.genSaltSync(10));
  }

  static checkPassword(password, hashed) {
    return bcrypt.compareSync(password, hashed);
  }
}

export default Protection;
