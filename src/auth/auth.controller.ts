import { Controller, Logger } from '@nestjs/common';
import { GrpcMethod } from '@nestjs/microservices';

import { AuthService } from './auth.service';
import {
  AUTH_SERVICE_NAME,
  SignInRequest,
  Token,
  type AuthResponse,
  type RefreshTokensResponse,
  type SignUpRequest,
} from 'src/generated-types/auth';
import type { User } from 'src/generated-types/user';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}
  protected readonly logger = new Logger(AuthController.name);

  @GrpcMethod(AUTH_SERVICE_NAME, 'SignUp')
  async signUp(data: SignUpRequest): Promise<User> {
    this.logger.log(`Received SignUp request for email: ${data.email}`);
    return await this.authService.signUp(data);
  }

  @GrpcMethod(AUTH_SERVICE_NAME, 'VerifyEmail')
  async verifyEmail(data: Token): Promise<AuthResponse> {
    this.logger.log(`Received VerifyEmail request with token: ${data.token}`);
    return await this.authService.verifyEmail(data.token);
  }

  @GrpcMethod(AUTH_SERVICE_NAME, 'SignIn')
  async signIn(data: SignInRequest): Promise<AuthResponse> {
    this.logger.log(`Received SignIn request for email: ${data.email}`);
    return await this.authService.signIn(data);
  }

  @GrpcMethod(AUTH_SERVICE_NAME, 'RefreshTokens')
  async refreshToken(data: Token): Promise<RefreshTokensResponse> {
    this.logger.log(`Received RefreshToken request with token: ${data.token}`);
    return await this.authService.refreshTokens(data.token);
  }
}
