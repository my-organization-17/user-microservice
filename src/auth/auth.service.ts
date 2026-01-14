import { Injectable, Logger } from '@nestjs/common';
import * as crypto from 'crypto';

import { PasswordHashService } from 'src/password-hash/password-hash.service';
import { PrismaService } from 'src/prisma/prisma.service';
import { AppError } from 'src/utils/errors/app-error';

import type { User } from 'prisma/generated-types/client';
import type { SignUpRequest } from 'src/generated-types/auth';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly passwordHashService: PasswordHashService,
  ) {}
  protected readonly logger = new Logger(AuthService.name);

  private generateToken(): string {
    return crypto.randomBytes(32).toString('hex');
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
          const token = this.generateToken();
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
          const token = this.generateToken();
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
      }

      const passwordHash = await this.passwordHashService.create(data.password);

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
      const token = this.generateToken();
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

  async verifyEmail(token: string): Promise<User> {
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

      // Update user's email verification status
      const updatedUser = await this.prisma.user.update({
        where: { id: emailVerification.userId },
        data: { isEmailVerified: true },
      });

      // Update the email verification record
      await this.prisma.emailVerificationToken.update({
        where: { token },
        data: { verifiedAt: new Date(), token: '' }, // Invalidate the token
      });

      this.logger.log(`Email verified for user ID: ${updatedUser.id}`);
      return updatedUser;
    } catch (error) {
      this.logger.error(`Error during email verification: ${error instanceof Error ? error.message : error}`);
      if (error instanceof AppError) throw error;
      throw AppError.internalServerError('Failed to verify email');
    }
  }
}
