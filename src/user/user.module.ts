import { Module } from '@nestjs/common';

import { HashService } from 'src/hash/hash.service';
import { UserService } from './user.service';
import { UserController } from './user.controller';

@Module({
  controllers: [UserController],
  providers: [UserService, HashService],
})
export class UserModule {}
