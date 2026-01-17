import { Injectable, Logger } from '@nestjs/common';

import { PrismaService } from 'src/prisma/prisma.service';

import type { EmailVerificationToken, User } from 'prisma/generated-types/client';

interface EmailVerificationTokenWithUser extends EmailVerificationToken {
  user: User;
}

@Injectable()
export class AuthRepository {
  constructor(private readonly prisma: PrismaService) {}
  protected readonly logger = new Logger(AuthRepository.name);

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
