import { Controller, Logger } from '@nestjs/common';
import { GrpcMethod } from '@nestjs/microservices';

import { type PasswordRequest, type UpdateUserRequest, USER_SERVICE_NAME } from 'src/generated-types/user';
import { UserService } from './user.service';

@Controller('user')
export class UserController {
  constructor(private readonly userService: UserService) {}
  protected readonly logger = new Logger(UserController.name);

  @GrpcMethod(USER_SERVICE_NAME, 'GetUserById')
  async getUserById({ id }: { id: string }) {
    this.logger.log(`Received GetUserById request for id: ${id}`);
    return this.userService.getUserById(id);
  }

  @GrpcMethod(USER_SERVICE_NAME, 'GetUserByEmail')
  async getUserByEmail({ email }: { email: string }) {
    this.logger.log(`Received GetUserByEmail request for email: ${email}`);
    return this.userService.getUserByEmail(email);
  }

  @GrpcMethod(USER_SERVICE_NAME, 'UpdateUser')
  async updateUser(data: UpdateUserRequest) {
    this.logger.log(`Received UpdateUser request for id: ${data.id}`);
    return this.userService.updateUser(data);
  }

  @GrpcMethod(USER_SERVICE_NAME, 'DeleteUser')
  async deleteUser({ id }: { id: string }) {
    this.logger.log(`Received DeleteUser request for id: ${id}`);
    return this.userService.deleteUser(id);
  }

  @GrpcMethod(USER_SERVICE_NAME, 'ConfirmPassword')
  async confirmPassword(data: PasswordRequest) {
    this.logger.log(`Received ConfirmPassword request for user id: ${data.id}`);
    return this.userService.confirmPassword(data);
  }

  @GrpcMethod(USER_SERVICE_NAME, 'ChangePassword')
  async changePassword(data: PasswordRequest) {
    this.logger.log(`Received ChangePassword request for user id: ${data.id}`);
    return this.userService.changePassword(data);
  }
}
