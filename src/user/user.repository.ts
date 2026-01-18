import { Injectable, Logger } from '@nestjs/common';

import { PrismaService } from 'src/prisma/prisma.service';
import type { BanDetails, User } from 'prisma/generated-types/client';
import type { SignUpRequest } from 'src/generated-types/auth';

@Injectable()
export class UserRepository {
  constructor(private readonly prisma: PrismaService) {}
  protected readonly logger = new Logger(UserRepository.name);

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

  // Update user
  async updateUser({ id, data }: { id: string; data: Partial<User> }): Promise<User> {
    this.logger.log(`Updating user with id: ${id}`);
    return await this.prisma.user.update({
      where: { id },
      data,
    });
  }

  // Delete user
  async deleteUser(id: string): Promise<void> {
    this.logger.log(`Deleting user with id: ${id}`);
    await this.prisma.user.delete({
      where: { id },
    });
  }

  // Get all banned users
  async getBannedUsers(): Promise<User[]> {
    this.logger.log('Fetching all banned users');
    return await this.prisma.user.findMany({
      where: { isBanned: true },
    });
  }

  // Get ban details by user id
  async getBanDetailsByUserId(userId: string): Promise<BanDetails[]> {
    this.logger.log(`Fetching ban details for user id: ${userId}`);
    return await this.prisma.banDetails.findMany({
      where: { userId },
    });
  }

  // Create ban details
  async createBanDetails(
    data: Pick<BanDetails, 'banReason' | 'banUntil' | 'userId' | 'isBanned' | 'bannedBy'>,
  ): Promise<BanDetails> {
    this.logger.log(`Creating ban details for user id: ${data.userId}`);
    return await this.prisma.banDetails.create({
      data,
    });
  }
}
