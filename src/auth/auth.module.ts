import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';

import { UserService } from 'src/user/user.service';
import { PasswordHashService } from 'src/password-hash/password-hash.service';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';

@Module({
  imports: [JwtModule.register({})],
  controllers: [AuthController],
  providers: [AuthService, UserService, PasswordHashService],
})
export class AuthModule {}
