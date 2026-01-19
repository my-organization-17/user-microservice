import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';

import { UserService } from 'src/user/user.service';
import { HashService } from 'src/hash/hash.service';
import { UserRepository } from 'src/user/user.repository';
import { RedisService } from 'src/redis/redis.service';

import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { AuthRepository } from './auth.repository';

@Module({
  imports: [JwtModule.register({})],
  controllers: [AuthController],
  providers: [AuthService, UserService, HashService, AuthRepository, UserRepository, RedisService],
})
export class AuthModule {}
