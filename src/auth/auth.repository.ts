import { Injectable, Logger } from '@nestjs/common';

import { PrismaService } from 'src/prisma/prisma.service';

import type { User } from 'prisma/generated-types/client';
import type { SignUpRequest } from 'src/generated-types/auth';
import type { EmailVerificationToken } from 'prisma/generated-types/browser';

interface EmailVerificationTokenWithUser extends EmailVerificationToken {
  user: User;
}

@Injectable()
export class AuthRepository {
  constructor(private readonly prisma: PrismaService) {}
  protected readonly logger = new Logger(AuthRepository.name);

  // Create a new user in the database
  async createUser({ data, passwordHash }: { data: SignUpRequest; passwordHash: string }): Promise<User> {
    this.logger.log(`Creating user with email: ${data.email}`);
    return await this.prisma.user.create({
      data: {
        email: data.email,
        passwordHash,
        name: data.name,
        phoneNumber: data.phoneNumber,
      },
    });
  }

  // find user by email
  async findUserByEmail(email: string): Promise<User | null> {
    this.logger.log(`Finding user by email: ${email}`);
    return await this.prisma.user.findUnique({
      where: { email },
    });
  }

  // find user by id
  async findUserById(id: string): Promise<User | null> {
    this.logger.log(`Finding user by id: ${id}`);
    return await this.prisma.user.findUnique({
      where: { id },
    });
  }

  // Update user
  async updateUser({ id, data }: { id: string; data: Partial<User> }): Promise<User> {
    this.logger.log(`Updating user with id: ${id}`);
    return await this.prisma.user.update({
      where: { id },
      data,
    });
  }

  // Find email verification token by token string
  async findEmailVerificationTokenByToken(token: string): Promise<EmailVerificationTokenWithUser | null> {
    this.logger.log(`Finding email verification token: ${token}`);
    return await this.prisma.emailVerificationToken.findUnique({
      where: { token },
      include: { user: true },
    });
  }

  // Find verification token by user ID
  async findEmailVerificationTokenByUserId(userId: string): Promise<EmailVerificationToken | null> {
    this.logger.log(`Finding email verification token for user ID: ${userId}`);
    return await this.prisma.emailVerificationToken.findUnique({
      where: { userId },
    });
  }

  // Create email verification token
  async createEmailVerificationToken({
    userId,
    token,
    expiresAt,
  }: {
    userId: string;
    token: string;
    expiresAt: Date;
  }): Promise<EmailVerificationToken> {
    this.logger.log(`Creating email verification token for user ID: ${userId}`);
    return await this.prisma.emailVerificationToken.create({
      data: {
        userId,
        token,
        expiresAt,
      },
    });
  }

  // Update email verification token
  async updateEmailVerificationToken({
    userId,
    token,
    expiresAt,
  }: {
    userId: string;
    token: string;
    expiresAt: Date;
  }): Promise<EmailVerificationToken | null> {
    this.logger.log(`Updating email verification token for user ID: ${userId}`);
    return await this.prisma.emailVerificationToken.update({
      where: { userId },
      data: {
        token,
        expiresAt,
      },
    });
  }
}
