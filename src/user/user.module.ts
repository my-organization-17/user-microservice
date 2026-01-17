import { Module } from '@nestjs/common';

import { HashService } from 'src/hash/hash.service';
import { UserService } from './user.service';
import { UserController } from './user.controller';
import { UserRepository } from './user.repository';

@Module({
  controllers: [UserController],
  providers: [UserService, HashService, UserRepository],
  exports: [],
})
export class UserModule {}
