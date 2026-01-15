import { Injectable, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';

import { HashService } from 'src/hash/hash.service';
import { PrismaService } from 'src/prisma/prisma.service';
import { AppError } from 'src/utils/errors/app-error';

import type { User } from 'prisma/generated-types/client';
import type { AuthResponse, RefreshTokensResponse, SignInRequest, SignUpRequest } from 'src/generated-types/auth';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly hashService: HashService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}
  protected readonly logger = new Logger(AuthService.name);

  private generateCryptoToken(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  private async generateJwtTokens(userId: string, isBanned: boolean): Promise<[string, string]> {
    return Promise.all([
      this.jwtService.signAsync(
        { sub: userId, isBanned },
        {
          secret: this.configService.get<string>('JWT_ACCESS_SECRET'),
          expiresIn: this.configService.get<number>('JWT_ACCESS_EXPIRATION'),
        },
      ),
      this.jwtService.signAsync(
        { sub: userId, isBanned },
        {
          secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
          expiresIn: this.configService.get<number>('JWT_REFRESH_EXPIRATION'),
        },
      ),
    ]);
  }

  async signUp(data: SignUpRequest): Promise<User> {
    this.logger.log(`Signing up user with email: ${data.email}`);
    try {
      // Check if user with the email already exists
      const existingUser = await this.prisma.user.findUnique({
        where: { email: data.email },
      });
      if (existingUser?.isEmailVerified) {
        this.logger.warn(`Email is already in use: ${data.email}`);
        throw AppError.conflict('Email is already in use');
      }
      if (existingUser) {
        const emailVerification = await this.prisma.emailVerificationToken.findUnique({
          where: { userId: existingUser.id },
        });
        if (!emailVerification) {
          const token = this.generateCryptoToken();
          await this.prisma.emailVerificationToken.create({
            data: {
              userId: existingUser.id,
              token,
              expiresAt: new Date(Date.now() + 1 * 60 * 60 * 1000), // 1 hour
            },
          });
          this.logger.log(`Resent email verification token for user ID: ${existingUser.id}`);
          throw AppError.conflict('Email is already in use but not verified. Verification email resent.');
        }
        if (emailVerification.expiresAt <= new Date()) {
          const token = this.generateCryptoToken();
          await this.prisma.emailVerificationToken.update({
            where: { userId: existingUser.id },
            data: {
              token,
              expiresAt: new Date(Date.now() + 1 * 60 * 60 * 1000), // 1 hour
            },
          });
          this.logger.log(`Resent expired email verification token for user ID: ${existingUser.id}`);
          throw AppError.conflict('Email is already in use but not verified. Verification email resent.');
        }
        this.logger.warn(`Email is already in use: ${data.email}`);
        throw AppError.conflict(
          'Email is already in use but not verified. Please check your email for verification link.',
        );
      }

      const passwordHash = await this.hashService.create(data.password);

      // Create new user
      const newUser = await this.prisma.user.create({
        data: {
          email: data.email,
          passwordHash,
          name: data.name,
          phoneNumber: data.phoneNumber,
        },
      });
      if (!newUser) {
        this.logger.error(`Failed to create user with email: ${data.email}`);
        throw AppError.internalServerError('Failed to create user');
      }

      // Create email verification token
      const token = this.generateCryptoToken();
      await this.prisma.emailVerificationToken.create({
        data: {
          userId: newUser.id,
          token,
          expiresAt: new Date(Date.now() + 1 * 60 * 60 * 1000), // 1 hour
        },
      });

      this.logger.log(`User created with ID: ${newUser.id}`);
      return newUser;
    } catch (error) {
      this.logger.error(`Error during sign up: ${error instanceof Error ? error.message : error}`);
      if (error instanceof AppError) throw error;
      throw AppError.internalServerError('Failed to sign up user');
    }
  }

  async verifyEmail(token: string): Promise<AuthResponse> {
    this.logger.log(`Verifying email with token: ${token}`);
    try {
      // Find the email verification record
      const emailVerification = await this.prisma.emailVerificationToken.findUnique({
        where: { token },
        include: { user: true },
      });
      if (!emailVerification) {
        this.logger.warn(`Invalid email verification token: ${token}`);
        throw AppError.badRequest('Invalid or expired email verification token');
      }
      if (emailVerification.expiresAt <= new Date()) {
        this.logger.warn(`Expired email verification token: ${token}`);
        throw AppError.badRequest('Invalid or expired email verification token');
      }

      // Update the email verification record
      await this.prisma.emailVerificationToken.update({
        where: { token },
        data: { verifiedAt: new Date(), token: '' }, // Invalidate the token
      });

      // Generate JWT tokens
      const [accessToken, refreshToken] = await this.generateJwtTokens(
        emailVerification.userId,
        emailVerification.user.isBanned,
      );

      // Update user record with hashed refresh token and set email as verified
      const updatedUser = await this.prisma.user.update({
        where: { id: emailVerification.userId },
        data: {
          refreshTokenHash: await this.hashService.create(refreshToken),
          isEmailVerified: true,
        },
      });

      this.logger.log(`Email verified for user ID: ${emailVerification.userId}`);
      return {
        accessToken,
        refreshToken,
        user: updatedUser,
      };
    } catch (error) {
      this.logger.error(`Error during email verification: ${error instanceof Error ? error.message : error}`);
      if (error instanceof AppError) throw error;
      throw AppError.internalServerError('Failed to verify email');
    }
  }

  async signIn(data: SignInRequest): Promise<AuthResponse> {
    this.logger.log(`Signing in user with email: ${data.email}`);
    try {
      // Find the user by email
      const user = await this.prisma.user.findUnique({
        where: { email: data.email },
      });
      if (!user) {
        this.logger.warn(`User not found with email: ${data.email}`);
        throw AppError.unauthorized('Invalid email or password');
      }

      // Verify password
      await this.hashService.compare(data.password, user.passwordHash);

      // Generate JWT tokens
      const [accessToken, refreshToken] = await this.generateJwtTokens(user.id, user.isBanned);

      // Update user record with hashed refresh token
      await this.prisma.user.update({
        where: { id: user.id },
        data: {
          refreshTokenHash: await this.hashService.create(refreshToken),
        },
      });

      this.logger.log(`User signed in with ID: ${user.id}`);
      return {
        accessToken,
        refreshToken,
        user,
      };
    } catch (error) {
      this.logger.error(`Error during sign in: ${error instanceof Error ? error.message : error}`);
      if (error instanceof AppError) throw error;
      throw AppError.internalServerError('Failed to sign in');
    }
  }

  async refreshTokens(token: string): Promise<RefreshTokensResponse> {
    this.logger.log(`Refreshing token`);
    try {
      // Verify the provided token
      const payload = await this.jwtService.verifyAsync<{ sub: string; isBanned: boolean }>(token, {
        secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
      });
      if (!payload || !payload.sub) {
        this.logger.warn(`Invalid refresh token`);
        throw AppError.unauthorized('Invalid refresh token');
      }

      // Find the user
      const user = await this.prisma.user.findUnique({
        where: { id: payload.sub },
      });
      if (!user || !user.refreshTokenHash) {
        this.logger.warn(`Invalid refresh token for user ID: ${payload.sub}`);
        throw AppError.unauthorized('Invalid refresh token');
      }

      // Verify the refresh token hash
      await this.hashService.validate(token, user.refreshTokenHash);

      // Generate new JWT tokens
      const [accessToken, refreshToken] = await this.generateJwtTokens(user.id, user.isBanned);

      // Update user record with new hashed refresh token
      await this.prisma.user.update({
        where: { id: user.id },
        data: {
          refreshTokenHash: await this.hashService.create(refreshToken),
        },
      });

      this.logger.log(`Tokens refreshed for user ID: ${user.id}`);
      return {
        accessToken,
        refreshToken,
      };
    } catch (error) {
      this.logger.error(`Error during token refresh: ${error instanceof Error ? error.message : error}`);
      if (error instanceof AppError) throw error;
      throw AppError.internalServerError('Failed to refresh token');
    }
  }
}
