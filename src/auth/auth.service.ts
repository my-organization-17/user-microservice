import { Injectable, Logger } from '@nestjs/common';
import * as crypto from 'crypto';

import { HashService } from 'src/hash/hash.service';
import { TokenService } from 'src/token/token.service';
import { UserRepository } from 'src/user/user.repository';
import { AppError } from 'src/utils/errors/app-error';
import { convertEnum } from 'src/utils/convertEnum';
import { RedisService } from 'src/redis/redis.service';
import { MessageBrokerService } from 'src/transport/message-broker/message-broker.service';
import { AuthRepository } from './auth.repository';

import { type StatusResponse, UserRole, type User } from 'src/generated-types/user';
import type { AuthResponse, RefreshTokensResponse, SignInRequest, SignUpRequest } from 'src/generated-types/auth';
import type { EmailRequest } from 'src/transport/message-broker/email.request.interface';

@Injectable()
export class AuthService {
  constructor(
    private readonly hashService: HashService,
    private readonly tokenService: TokenService,
    private readonly authRepository: AuthRepository,
    private readonly userRepository: UserRepository,
    private readonly redisService: RedisService,
    private readonly messageBrokerService: MessageBrokerService,
  ) {}
  protected readonly logger = new Logger(AuthService.name);

  private generateCryptoToken(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  private sendVerificationEmail(to: string, token: string, name?: string | null): void {
    this.messageBrokerService.emitMessage('notification.email.send', {
      to,
      subject: 'Verify your email',
      template: 'verify-email',
      context: {
        name: name || 'New User',
        verificationLink: `https://yourapp.com/verify-email?token=${token}`,
      },
    } as EmailRequest);
  }

  private sendPasswordResetEmail(to: string, token: string, name?: string | null): void {
    this.messageBrokerService.emitMessage('notification.email.send', {
      to,
      subject: 'Reset your password',
      template: 'reset-password',
      context: {
        name: name || 'User',
        resetLink: `https://yourapp.com/reset-password?token=${token}`,
      },
    } as EmailRequest);
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
          this.sendVerificationEmail(existingUser.email, token, existingUser.name);
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
          this.sendVerificationEmail(existingUser.email, token, existingUser.name);
          this.logger.log(`Resent expired email verification token for user ID: ${existingUser.id}`);
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

      // Send verification email
      this.sendVerificationEmail(newUser.email, token, newUser.name);

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

  async resendConfirmationEmail(email: string): Promise<StatusResponse> {
    this.logger.log(`Resending confirmation email to: ${email}`);
    try {
      const user = await this.userRepository.findUserByEmail(email);
      if (!user) {
        this.logger.warn(`User not found with email: ${email}`);
        throw AppError.badRequest('User with the provided email does not exist');
      }
      if (user.isEmailVerified) {
        this.logger.warn(`Email is already verified: ${email}`);
        throw AppError.badRequest('Email is already verified');
      }

      const emailVerification = await this.authRepository.findEmailVerificationTokenByUserId(user.id);
      const token = this.generateCryptoToken();
      if (emailVerification) {
        await this.authRepository.updateEmailVerificationToken({
          userId: user.id,
          token,
          expiresAt: new Date(Date.now() + 1 * 60 * 60 * 1000), // 1 hour
        });
        this.sendVerificationEmail(user.email, token, user.name);
        this.logger.log(`Updated email verification token for user ID: ${user.id}`);
      } else {
        await this.authRepository.createEmailVerificationToken({
          userId: user.id,
          token,
          expiresAt: new Date(Date.now() + 1 * 60 * 60 * 1000), // 1 hour
        });
        this.sendVerificationEmail(user.email, token, user.name);
        this.logger.log(`Created email verification token for user ID: ${user.id}`);
      }

      return { success: true, message: 'Confirmation email resent successfully' };
    } catch (error) {
      this.logger.error(`Error during resending confirmation email: ${error instanceof Error ? error.message : error}`);
      if (error instanceof AppError) throw error;
      throw AppError.internalServerError('Failed to resend confirmation email');
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
      if (emailVerification.verifiedAt) {
        this.logger.warn(`Email already verified for token: ${token}`);
        throw AppError.badRequest('Email is already verified');
      }

      // Update the email verification record
      await this.authRepository.updateEmailVerificationToken({
        userId: emailVerification.userId,
        token: '',
        verifiedAt: new Date(),
      });

      // Generate JWT tokens
      const { accessToken, refreshToken } = await this.tokenService.generateJwtTokens({
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

      // Check if email is verified
      if (!user.isEmailVerified) {
        const emailVerification = await this.authRepository.findEmailVerificationTokenByUserId(user.id);
        if (!emailVerification) {
          const token = this.generateCryptoToken();
          await this.authRepository.createEmailVerificationToken({
            userId: user.id,
            token,
            expiresAt: new Date(Date.now() + 1 * 60 * 60 * 1000), // 1 hour
          });
          this.sendVerificationEmail(user.email, token, user.name);
          this.logger.log(`Resent email verification token for user ID: ${user.id}`);
          throw AppError.unauthorized('Email not verified. Verification email resent.');
        }
        if (emailVerification.expiresAt <= new Date()) {
          const token = this.generateCryptoToken();
          await this.authRepository.updateEmailVerificationToken({
            userId: user.id,
            token,
            expiresAt: new Date(Date.now() + 1 * 60 * 60 * 1000), // 1 hour
          });
          this.sendVerificationEmail(user.email, token, user.name);
          this.logger.log(`Resent expired email verification token for user ID: ${user.id}`);
          throw AppError.unauthorized('Email not verified. Verification email resent.');
        }
        this.logger.warn(`Email not verified for user with email: ${data.email}`);
        throw AppError.unauthorized('Email not verified. Please check your email for verification link.');
      }

      // Verify password
      const isPasswordValid = await this.hashService.compare(data.password, user.passwordHash);
      if (!isPasswordValid) {
        this.logger.warn(`Invalid password for user with email: ${data.email}`);
        throw AppError.unauthorized('Invalid email or password');
      }

      // Update last login timestamp
      await this.userRepository.updateUser({
        id: user.id,
        data: { lastLoginAt: new Date() },
      });

      // Generate JWT tokens
      const { accessToken, refreshToken } = await this.tokenService.generateJwtTokens({
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
      const payload = await this.tokenService.verifyJwtToken<{ sub: string; isBanned: boolean; sid: string }>(token);
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
      const key = this.tokenService.refreshKey(payload.sub, payload.sid);
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
      const { accessToken, refreshToken } = await this.tokenService.generateJwtTokens({
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

  async initResetPassword(email: string): Promise<StatusResponse> {
    this.logger.log(`Initiating password reset for email: ${email}`);
    const user = await this.userRepository.findUserByEmail(email);
    if (!user) {
      this.logger.warn(`User not found with email: ${email}`);
      throw AppError.badRequest('User with the provided email does not exist');
    }
    if (!user.isEmailVerified) {
      this.logger.warn(`Email not verified for user with email: ${email}`);
      throw AppError.badRequest('Email is not verified');
    }

    // Check if a password reset token already exists for the user
    const existingToken = await this.authRepository.findPasswordResetTokenByToken(user.id);
    if (existingToken && existingToken.expiresAt > new Date()) {
      this.logger.log(`Existing valid password reset token found for user ID: ${user.id}`);
      throw AppError.badRequest('A valid password reset token already exists');
    }

    // Create a new password reset token
    const token = this.generateCryptoToken();
    if (existingToken) {
      await this.authRepository.updatePasswordResetTokenById({
        id: existingToken.id,
        token,
        expiresAt: new Date(Date.now() + 1 * 60 * 60 * 1000), // 1 hour
      });
      this.logger.log(`Updated password reset token for user ID: ${user.id}`);
    } else {
      await this.authRepository.createPasswordResetToken({
        userId: user.id,
        token,
        expiresAt: new Date(Date.now() + 1 * 60 * 60 * 1000), // 1 hour
      });
      this.logger.log(`Created password reset token for user ID: ${user.id}`);
    }

    // Send password reset email
    this.sendPasswordResetEmail(user.email, token, user.name);
    this.logger.log(`Password reset email sent to user ID: ${user.id}`);

    return { success: true, message: 'Password reset token generated successfully' };
  }

  async resendResetPasswordEmail(email: string): Promise<StatusResponse> {
    this.logger.log(`Resending password reset email to: ${email}`);
    const user = await this.userRepository.findUserByEmail(email);
    if (!user) {
      this.logger.warn(`User not found with email: ${email}`);
      throw AppError.badRequest('User with the provided email does not exist');
    }
    if (!user.isEmailVerified) {
      this.logger.warn(`Email not verified for user with email: ${email}`);
      throw AppError.badRequest('Email is not verified');
    }

    // Find existing password reset token
    const passwordReset = await this.authRepository.findPasswordResetTokenByToken(user.id);
    if (!passwordReset || passwordReset.expiresAt <= new Date()) {
      this.logger.warn(`No valid password reset token found for user ID: ${user.id}`);
      throw AppError.badRequest('No valid password reset token found. Please initiate password reset again.');
    }

    // Resend password reset email
    this.sendPasswordResetEmail(user.email, passwordReset.token, user.name);
    this.logger.log(`Password reset email resent to user ID: ${user.id}`);

    return { success: true, message: 'Password reset email resent successfully' };
  }

  async setNewPassword(token: string, password: string): Promise<StatusResponse> {
    this.logger.log(`Setting new password with token: ${token}`);
    // Find the password reset record
    const passwordReset = await this.authRepository.findPasswordResetTokenByToken(token);
    if (!passwordReset) {
      this.logger.warn(`Invalid password reset token: ${token}`);
      throw AppError.badRequest('Invalid or expired password reset token');
    }
    if (passwordReset.expiresAt <= new Date()) {
      this.logger.warn(`Expired password reset token: ${token}`);
      throw AppError.badRequest('Invalid or expired password reset token');
    }

    // find the user
    const user = await this.userRepository.findUserById(passwordReset.userId);
    if (!user) {
      this.logger.warn(`User not found with ID: ${passwordReset.userId}`);
      throw AppError.badRequest('Invalid password reset token');
    }

    // Ensure the new password is different from the old one
    await this.hashService.same(password, user.passwordHash);

    // Hash the new password
    const passwordHash = await this.hashService.create(password);

    // Update the user's password
    await this.userRepository.updateUser({
      id: passwordReset.userId,
      data: { passwordHash },
    });

    // Invalidate the used password reset token
    await this.authRepository.updatePasswordResetTokenById({
      id: passwordReset.id,
      token: '',
      changedAt: new Date(),
    });
    this.logger.log(`Password reset successfully for user ID: ${passwordReset.userId}`);
    return { success: true, message: 'Password reset successfully' };
  }
}
