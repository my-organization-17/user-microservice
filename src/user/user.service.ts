import { Injectable, Logger } from '@nestjs/common';
import { User } from 'prisma/generated-types/client';
import { CreateUserRequest, PasswordRequest, StatusResponse, UpdateUserRequest } from 'src/generated-types/user';
import { PasswordHashService } from 'src/password-hash/password-hash.service';

import { PrismaService } from 'src/prisma/prisma.service';
import { AppError } from 'src/utils/errors/app-error';

@Injectable()
export class UserService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly passwordHashService: PasswordHashService,
  ) {}
  protected readonly logger = new Logger(UserService.name);

  async getUserById(id: string): Promise<User> {
    this.logger.log(`Fetching user by ID: ${id}`);
    try {
      const user = await this.prisma.user.findUnique({
        where: { id },
      });
      if (!user) {
        this.logger.warn(`User not found with ID: ${id}`);
        throw AppError.notFound('User not found');
      }
      return user;
    } catch (error) {
      this.logger.error(`Error fetching user: ${error instanceof Error ? error.message : error}`);
      if (error instanceof AppError) throw error;
      throw AppError.internalServerError('Failed to fetch user');
    }
  }

  async getUserByEmail(email: string): Promise<User> {
    this.logger.log(`Fetching user by email: ${email}`);
    try {
      const user = await this.prisma.user.findUnique({
        where: { email },
      });
      if (!user) {
        this.logger.warn(`User not found with email: ${email}`);
        throw AppError.notFound('User not found');
      }
      return user;
    } catch (error) {
      this.logger.error(`Error fetching user: ${error instanceof Error ? error.message : error}`);
      if (error instanceof AppError) throw error;
      throw AppError.internalServerError('Failed to fetch user');
    }
  }

  async createUser(data: CreateUserRequest): Promise<User> {
    this.logger.log(`Creating user with email: ${data.email}`);
    try {
      const existingUser = await this.prisma.user.findUnique({
        where: { email: data.email },
      });
      if (existingUser) {
        this.logger.warn(`User already exists with email: ${data.email}`);
        throw AppError.conflict('User with this email already exists');
      }

      const newUser = await this.prisma.user.create({
        data,
      });
      this.logger.log(`User created with ID: ${newUser.id}`);
      return newUser;
    } catch (error) {
      this.logger.error(`Error creating user: ${error instanceof Error ? error.message : error}`);
      if (error instanceof AppError) throw error;
      throw AppError.internalServerError('Failed to create user');
    }
  }

  async updateUser(data: UpdateUserRequest): Promise<User> {
    this.logger.log(`Updating user with ID: ${data.id}`);
    try {
      const user = await this.prisma.user.findUnique({
        where: { id: data.id },
      });
      if (!user) {
        this.logger.warn(`User not found with ID: ${data.id}`);
        throw AppError.notFound('User not found');
      }

      const updatedUser = await this.prisma.user.update({
        where: { id: data.id },
        data,
      });
      this.logger.log(`User updated with ID: ${data.id}`);
      return updatedUser;
    } catch (error) {
      this.logger.error(`Error updating user: ${error instanceof Error ? error.message : error}`);
      if (error instanceof AppError) throw error;
      throw AppError.internalServerError('Failed to update user');
    }
  }

  async deleteUser(id: string): Promise<StatusResponse> {
    this.logger.log(`Deleting user with ID: ${id}`);
    try {
      const user = await this.prisma.user.findUnique({
        where: { id },
      });
      if (!user) {
        this.logger.warn(`User not found with ID: ${id}`);
        throw AppError.notFound('User not found');
      }

      await this.prisma.user.delete({
        where: { id },
      });
      this.logger.log(`User deleted with ID: ${id}`);
      return { success: true, message: 'User deleted successfully' };
    } catch (error) {
      this.logger.error(`Error deleting user: ${error instanceof Error ? error.message : error}`);
      if (error instanceof AppError) throw error;
      throw AppError.internalServerError('Failed to delete user');
    }
  }

  async confirmPassword(data: PasswordRequest): Promise<StatusResponse> {
    this.logger.log(`Confirming password for user ID: ${data.id}`);
    try {
      const user = await this.prisma.user.findUnique({
        where: { id: data.id },
      });
      if (!user) {
        this.logger.warn(`User not found with ID: ${data.id}`);
        throw AppError.notFound('User not found');
      }

      const isMatch = await this.passwordHashService.compare(data.password, user.passwordHash);
      if (!isMatch) {
        this.logger.warn(`Password mismatch for user ID: ${data.id}`);
        throw AppError.badRequest('Invalid password');
      }

      this.logger.log(`Password confirmed for user ID: ${data.id}`);
      return { success: true, message: 'Password confirmed successfully' };
    } catch (error) {
      this.logger.error(`Error confirming password: ${error instanceof Error ? error.message : error}`);
      if (error instanceof AppError) throw error;
      throw AppError.internalServerError('Failed to confirm password');
    }
  }

  async changePassword(data: PasswordRequest): Promise<StatusResponse> {
    this.logger.log(`Changing password for user ID: ${data.id}`);
    try {
      const user = await this.prisma.user.findUnique({
        where: { id: data.id },
      });
      if (!user) {
        this.logger.warn(`User not found with ID: ${data.id}`);
        throw AppError.notFound('User not found');
      }

      const newPasswordHash = await this.passwordHashService.create(data.password);
      await this.prisma.user.update({
        where: { id: data.id },
        data: { passwordHash: newPasswordHash },
      });

      this.logger.log(`Password changed for user ID: ${data.id}`);
      return { success: true, message: 'Password changed successfully' };
    } catch (error) {
      this.logger.error(`Error changing password: ${error instanceof Error ? error.message : error}`);
      if (error instanceof AppError) throw error;
      throw AppError.internalServerError('Failed to change password');
    }
  }
}
