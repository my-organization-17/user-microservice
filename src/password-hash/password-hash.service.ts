import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcryptjs';

import { AppError } from 'src/utils/errors/app-error';

@Injectable()
export class PasswordHashService {
  private readonly index = 5;

  async create(password: string): Promise<string> {
    const salt = await bcrypt.genSalt(this.index);
    const passwordHash = await bcrypt.hash(password, salt);
    if (!passwordHash) {
      throw AppError.forbidden("Can't create password hash");
    }
    return passwordHash;
  }

  async compare(password: string, passwordHash: string): Promise<boolean> {
    const isValidPass = await bcrypt.compare(password, passwordHash);
    if (!isValidPass) {
      throw AppError.badRequest('Password not match');
    }
    return isValidPass;
  }
}
