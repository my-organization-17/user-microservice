import { Injectable, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';

import { HashService } from 'src/hash/hash.service';
import { UserRepository } from 'src/user/user.repository';
import { AppError } from 'src/utils/errors/app-error';
import { convertEnum } from 'src/utils/convertEnum';
import { RedisService } from 'src/redis/redis.service';
import { AuthRepository } from './auth.repository';

import type { AuthResponse, RefreshTokensResponse, SignInRequest, SignUpRequest } from 'src/generated-types/auth';
import { UserRole, type User } from 'src/generated-types/user';

@Injectable()
export class AuthService {
  constructor(
    private readonly hashService: HashService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly authRepository: AuthRepository,
    private readonly userRepository: UserRepository,
    private readonly redisService: RedisService,
  ) {}
  protected readonly logger = new Logger(AuthService.name);

  private generateCryptoToken(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  private refreshKey(userId: string, sessionId: string) {
    return `refresh:${userId}:${sessionId}`;
  }

  private async generateJwtTokens({
    userId,
    isBanned,
    role,
    sid,
  }: {
    userId: string;
    isBanned: boolean;
    role: UserRole;
    sid?: string;
  }): Promise<RefreshTokensResponse> {
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(
        { sub: userId, isBanned, role, sid },
        {
          secret: this.configService.get<string>('JWT_ACCESS_SECRET'),
          expiresIn: this.configService.get<number>('JWT_ACCESS_EXPIRATION'),
        },
      ),
      this.jwtService.signAsync(
        { sub: userId, isBanned, role, sid },
        {
          secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
          expiresIn: this.configService.get<number>('JWT_REFRESH_EXPIRATION'),
        },
      ),
    ]);

    const hash = await this.hashService.create(refreshToken);

    await this.redisService.set(
      this.refreshKey(userId, sid ?? ''),
      hash,
      'EX',
      this.configService.getOrThrow<number>('JWT_REFRESH_EXPIRATION'),
    );
    return { accessToken, refreshToken };
  }

  async signUp(data: SignUpRequest): Promise<User> {
    this.logger.log(`Signing up user with email: ${data.email}`);
    try {
      // Check if user with the email already exists
      const existingUser = await this.userRepository.findUserByEmail(data.email);
      if (existingUser?.isEmailVerified) {
        this.logger.warn(`Email is already in use: ${data.email}`);
        throw AppError.conflict('Email is already in use');
      }
      if (existingUser) {
        const emailVerification = await this.authRepository.findEmailVerificationTokenByUserId(existingUser.id);
        if (!emailVerification) {
          const token = this.generateCryptoToken();
          await this.authRepository.createEmailVerificationToken({
            userId: existingUser.id,
            token,
            expiresAt: new Date(Date.now() + 1 * 60 * 60 * 1000), // 1 hour
          });
          this.logger.log(`Resent email verification token for user ID: ${existingUser.id}`);
          throw AppError.conflict('Email is already in use but not verified. Verification email resent.');
        }
        if (emailVerification.expiresAt <= new Date()) {
          const token = this.generateCryptoToken();
          await this.authRepository.updateEmailVerificationToken({
            userId: existingUser.id,
            token,
            expiresAt: new Date(Date.now() + 1 * 60 * 60 * 1000), // 1 hour
          });
          this.logger.log(`Resent expired email verification token for user ID: ${existingUser.id}`);
          throw AppError.conflict('Email is already in use but not verified. Verification email resent.');
        }
        this.logger.warn(`Email is already in use: ${data.email}`);
        throw AppError.conflict(
          'Email is already in use but not verified. Please check your email for verification link.',
        );
      }

      // Create new user
      const passwordHash = await this.hashService.create(data.password);
      const newUser = await this.userRepository.createUser({ data, passwordHash });
      if (!newUser) {
        this.logger.error(`Failed to create user with email: ${data.email}`);
        throw AppError.internalServerError('Failed to create user');
      }

      // Create email verification token
      const token = this.generateCryptoToken();
      await this.authRepository.createEmailVerificationToken({
        userId: newUser.id,
        token,
        expiresAt: new Date(Date.now() + 1 * 60 * 60 * 1000), // 1 hour
      });

      this.logger.log(`User created with ID: ${newUser.id}`);
      return {
        ...newUser,
        role: convertEnum(UserRole, newUser.role),
      };
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
      const emailVerification = await this.authRepository.findEmailVerificationTokenByToken(token);
      if (!emailVerification) {
        this.logger.warn(`Invalid email verification token: ${token}`);
        throw AppError.badRequest('Invalid or expired email verification token');
      }
      if (emailVerification.expiresAt <= new Date()) {
        this.logger.warn(`Expired email verification token: ${token}`);
        throw AppError.badRequest('Invalid or expired email verification token');
      }

      // Update the email verification record
      await this.authRepository.updateEmailVerificationToken({
        userId: emailVerification.userId,
        token: '',
        expiresAt: new Date(),
      });

      // Generate JWT tokens
      const { accessToken, refreshToken } = await this.generateJwtTokens({
        userId: emailVerification.userId,
        isBanned: emailVerification.user.isBanned,
        role: convertEnum(UserRole, emailVerification.user.role),
        sid: crypto.randomUUID(),
      });

      // Update user's isEmailVerified status
      const updatedUser = await this.userRepository.updateUser({
        id: emailVerification.userId,
        data: { isEmailVerified: true },
      });

      this.logger.log(`Email verified for user ID: ${emailVerification.userId}`);
      return {
        accessToken,
        refreshToken,
        user: {
          ...updatedUser,
          role: convertEnum(UserRole, updatedUser.role),
        },
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
      const user = await this.userRepository.findUserByEmail(data.email);
      if (!user) {
        this.logger.warn(`User not found with email: ${data.email}`);
        throw AppError.unauthorized('Invalid email or password');
      }

      // Verify password
      await this.hashService.compare(data.password, user.passwordHash);

      // Generate JWT tokens
      const { accessToken, refreshToken } = await this.generateJwtTokens({
        userId: user.id,
        isBanned: user.isBanned,
        role: convertEnum(UserRole, user.role),
        sid: crypto.randomUUID(),
      });

      this.logger.log(`User signed in with ID: ${user.id}`);
      return {
        accessToken,
        refreshToken,
        user: {
          ...user,
          role: convertEnum(UserRole, user.role),
        },
      };
    } catch (error) {
      this.logger.error(`Error during sign in: ${error instanceof Error ? error.message : error}`);
      if (error instanceof AppError) throw error;
      throw AppError.internalServerError('Failed to sign in');
    }
  }

  async refreshTokens(token: string): Promise<RefreshTokensResponse> {
    this.logger.log(`Refreshing token`);
    if (!token) {
      this.logger.warn(`No refresh token provided`);
      throw AppError.unauthorized('No refresh token provided');
    }
    try {
      // Verify the provided token
      const payload = await this.jwtService.verifyAsync<{ sub: string; isBanned: boolean; sid: string }>(token, {
        secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
      });
      if (!payload || !payload.sub) {
        this.logger.warn(`Invalid refresh token`);
        throw AppError.unauthorized('Invalid refresh token');
      }

      // Find the user
      const user = await this.userRepository.findUserById(payload.sub);
      if (!user) {
        this.logger.warn(`User not found with ID: ${payload.sub}`);
        throw AppError.unauthorized('Invalid refresh token');
      }

      // Retrieve the stored refresh token hash from Redis
      const key = this.refreshKey(payload.sub, payload.sid);
      this.logger.log(`Retrieving refresh token hash from Redis with key: ${key}`);
      const storedHash = await this.redisService.get(key);
      if (!storedHash) {
        this.logger.warn(`No refresh token hash found in Redis for user ID: ${user.id}`);
        throw AppError.unauthorized('Invalid token');
      }

      // Verify the refresh token hash
      const isValid = await this.hashService.validate(token, storedHash);

      // Delete the old refresh token from Redis
      await this.redisService.del(key);

      if (!isValid) {
        this.logger.warn('Invalid token');
        throw AppError.unauthorized('Invalid token');
      }

      // Generate new JWT tokens
      const { accessToken, refreshToken } = await this.generateJwtTokens({
        userId: user.id,
        isBanned: user.isBanned,
        role: convertEnum(UserRole, user.role),
        sid: crypto.randomUUID(),
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
