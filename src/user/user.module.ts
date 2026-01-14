import { Module } from '@nestjs/common';

import { PasswordHashService } from 'src/password-hash/password-hash.service';
import { UserService } from './user.service';
import { UserController } from './user.controller';

@Module({
  controllers: [UserController],
  providers: [UserService, PasswordHashService],
})
export class UserModule {}
