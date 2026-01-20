import { Module } from '@nestjs/common';

import { HashService } from 'src/hash/hash.service';
import { UserRepository } from 'src/user/user.repository';
import { RedisService } from 'src/redis/redis.service';

import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { AuthRepository } from './auth.repository';
import { TokenService } from 'src/token/token.service';

@Module({
  imports: [],
  controllers: [AuthController],
  providers: [AuthService, AuthRepository, HashService, RedisService, TokenService, UserRepository],
})
export class AuthModule {}
