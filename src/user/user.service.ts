import { Injectable, Logger } from '@nestjs/common';

import { HashService } from 'src/hash/hash.service';
import { AppError } from 'src/utils/errors/app-error';
import { convertEnum } from 'src/utils/convertEnum';

import {
  UserRole,
  type PasswordRequest,
  type StatusResponse,
  type UpdateUserRequest,
  type User,
} from 'src/generated-types/user';
import { UserRepository } from './user.repository';

@Injectable()
export class UserService {
  constructor(
    private readonly hashService: HashService,
    private readonly userRepository: UserRepository,
  ) {}
  protected readonly logger = new Logger(UserService.name);

  async getUserById(id: string): Promise<User> {
    this.logger.log(`Fetching user by ID: ${id}`);
    try {
      const user = await this.userRepository.findUserById(id);
      if (!user) {
        this.logger.warn(`User not found with ID: ${id}`);
        throw AppError.notFound('User not found');
      }
      return {
        ...user,
        role: convertEnum(UserRole, user.role),
      };
    } catch (error) {
      this.logger.error(`Error fetching user: ${error instanceof Error ? error.message : error}`);
      if (error instanceof AppError) throw error;
      throw AppError.internalServerError('Failed to fetch user');
    }
  }

  async getUserByEmail(email: string): Promise<User> {
    this.logger.log(`Fetching user by email: ${email}`);
    try {
      const user = await this.userRepository.findUserByEmail(email);
      if (!user) {
        this.logger.warn(`User not found with email: ${email}`);
        throw AppError.notFound('User not found');
      }
      return {
        ...user,
        role: convertEnum(UserRole, user.role),
      };
    } catch (error) {
      this.logger.error(`Error fetching user: ${error instanceof Error ? error.message : error}`);
      if (error instanceof AppError) throw error;
      throw AppError.internalServerError('Failed to fetch user');
    }
  }

  async updateUser(data: UpdateUserRequest): Promise<User> {
    this.logger.log(`Updating user with ID: ${data.id}`);
    try {
      const user = await this.userRepository.findUserById(data.id);
      if (!user) {
        this.logger.warn(`User not found with ID: ${data.id}`);
        throw AppError.notFound('User not found');
      }

      const updatedUser = await this.userRepository.updateUser({ id: data.id, data });
      this.logger.log(`User updated with ID: ${data.id}`);
      return {
        ...updatedUser,
        role: convertEnum(UserRole, updatedUser.role),
      };
    } catch (error) {
      this.logger.error(`Error updating user: ${error instanceof Error ? error.message : error}`);
      if (error instanceof AppError) throw error;
      throw AppError.internalServerError('Failed to update user');
    }
  }

  async deleteUser(id: string): Promise<StatusResponse> {
    this.logger.log(`Deleting user with ID: ${id}`);
    try {
      const user = await this.userRepository.findUserById(id);
      if (!user) {
        this.logger.warn(`User not found with ID: ${id}`);
        throw AppError.notFound('User not found');
      }

      await this.userRepository.deleteUser(id);
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
      const user = await this.userRepository.findUserById(data.id);
      if (!user) {
        this.logger.warn(`User not found with ID: ${data.id}`);
        throw AppError.notFound('User not found');
      }

      const isMatch = await this.hashService.compare(data.password, user.passwordHash);
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
      const user = await this.userRepository.findUserById(data.id);
      if (!user) {
        this.logger.warn(`User not found with ID: ${data.id}`);
        throw AppError.notFound('User not found');
      }

      const newPasswordHash = await this.hashService.create(data.password);
      await this.userRepository.updateUser({ id: data.id, data: { passwordHash: newPasswordHash } });

      this.logger.log(`Password changed for user ID: ${data.id}`);
      return { success: true, message: 'Password changed successfully' };
    } catch (error) {
      this.logger.error(`Error changing password: ${error instanceof Error ? error.message : error}`);
      if (error instanceof AppError) throw error;
      throw AppError.internalServerError('Failed to change password');
    }
  }
}
