import { Controller, Logger } from '@nestjs/common';
import { GrpcMethod } from '@nestjs/microservices';

import { AuthService } from './auth.service';
import { AUTH_SERVICE_NAME, type SignUpRequest } from 'src/generated-types/auth';
import type { User } from 'src/generated-types/user';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}
  protected readonly logger = new Logger(AuthController.name);

  @GrpcMethod(AUTH_SERVICE_NAME, 'SignUp')
  async signUp(data: SignUpRequest): Promise<User> {
    this.logger.log(`Received SignUp request for email: ${data.email}`);
    const user = await this.authService.signUp(data);
    return user;
  }

  @GrpcMethod(AUTH_SERVICE_NAME, 'VerifyEmail')
  async verifyEmail(data: { token: string }): Promise<User> {
    this.logger.log(`Received VerifyEmail request with token: ${data.token}`);
    const user = await this.authService.verifyEmail(data.token);
    return user;
  }
}
