import { Test, TestingModule } from '@nestjs/testing';

import { UserService } from '../user.service';
import { UserRepository } from '../user.repository';
import { HashService } from 'src/hash/hash.service';
import { AppError } from 'src/utils/errors/app-error';
import { UserRole } from 'src/generated-types/user';

describe('UserService', () => {
  let service: UserService;

  const baseUser = {
    id: 'user-1',
    email: 'test@test.com',
    passwordHash: 'hash',
    role: 'USER',
    isBanned: false,
    name: 'Test User',
  };

  const hashServiceMock = {
    compare: jest.fn(),
    same: jest.fn(),
    create: jest.fn(),
  };

  const userRepositoryMock = {
    findUserById: jest.fn(),
    updateUser: jest.fn(),
    deleteUser: jest.fn(),
    getBannedUsers: jest.fn(),
    getBanDetailsByUserId: jest.fn(),
    createBanDetails: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UserService,
        { provide: HashService, useValue: hashServiceMock },
        { provide: UserRepository, useValue: userRepositoryMock },
      ],
    }).compile();

    service = module.get<UserService>(UserService);
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('getUserById', () => {
    it('should return user when found', async () => {
      userRepositoryMock.findUserById.mockResolvedValue(baseUser);

      const result = await service.getUserById('user-1');

      expect(result.id).toBe('user-1');
      expect(result.role).toBe(UserRole.USER);
    });

    it('should throw not found if user does not exist', async () => {
      userRepositoryMock.findUserById.mockResolvedValue(null);

      await expect(service.getUserById('user-1')).rejects.toBeInstanceOf(AppError);
    });
  });

  describe('updateUser', () => {
    it('should update and return user', async () => {
      userRepositoryMock.findUserById.mockResolvedValue(baseUser);
      userRepositoryMock.updateUser.mockResolvedValue({
        ...baseUser,
        name: 'New Name',
      });

      const result = await service.updateUser({
        id: 'user-1',
        name: 'New Name',
      });

      expect(result.name).toBe('New Name');
      expect(userRepositoryMock.updateUser).toHaveBeenCalled();
    });
  });

  describe('deleteUser', () => {
    it('should delete user', async () => {
      userRepositoryMock.findUserById.mockResolvedValue(baseUser);

      const result = await service.deleteUser('user-1');

      expect(userRepositoryMock.deleteUser).toHaveBeenCalledWith('user-1');
      expect(result.success).toBe(true);
    });
  });

  describe('confirmPassword', () => {
    it('should confirm password', async () => {
      userRepositoryMock.findUserById.mockResolvedValue(baseUser);
      hashServiceMock.compare.mockResolvedValue(true);

      const result = await service.confirmPassword({
        id: 'user-1',
        password: 'password',
      });

      expect(result.success).toBe(true);
    });

    it('should throw if password is invalid', async () => {
      userRepositoryMock.findUserById.mockResolvedValue(baseUser);
      hashServiceMock.compare.mockResolvedValue(false);

      await expect(service.confirmPassword({ id: 'user-1', password: 'wrong' })).rejects.toBeInstanceOf(AppError);
    });
  });

  describe('changePassword', () => {
    it('should change password', async () => {
      userRepositoryMock.findUserById.mockResolvedValue(baseUser);
      hashServiceMock.same.mockResolvedValue(false);
      hashServiceMock.create.mockResolvedValue('new-hash');

      const result = await service.changePassword({
        id: 'user-1',
        password: 'new-password',
      });

      expect(hashServiceMock.create).toHaveBeenCalled();
      expect(userRepositoryMock.updateUser).toHaveBeenCalled();
      expect(result.success).toBe(true);
    });
  });

  describe('banUser', () => {
    it('should ban user', async () => {
      userRepositoryMock.findUserById.mockResolvedValue(baseUser);
      userRepositoryMock.updateUser.mockResolvedValue({
        ...baseUser,
        isBanned: true,
      });

      const result = await service.banUser({
        id: 'user-1',
        bannedBy: 'admin',
      });

      expect(result.isBanned).toBe(true);
    });
  });

  describe('unbanUser', () => {
    it('should unban user', async () => {
      userRepositoryMock.findUserById.mockResolvedValue({
        ...baseUser,
        isBanned: true,
      });
      userRepositoryMock.updateUser.mockResolvedValue({
        ...baseUser,
        isBanned: false,
      });

      const result = await service.unbanUser({
        id: 'user-1',
        bannedBy: 'admin',
      });

      expect(result.isBanned).toBe(false);
    });
  });

  describe('getBannedUsers', () => {
    it('should return banned users', async () => {
      userRepositoryMock.getBannedUsers.mockResolvedValue([{ ...baseUser, isBanned: true }]);

      const result = await service.getBannedUsers();

      expect(result.users.length).toBe(1);
      expect(result.users[0].isBanned).toBe(true);
    });
  });

  describe('getBanDetailsByUserId', () => {
    it('should return ban details', async () => {
      userRepositoryMock.getBanDetailsByUserId.mockResolvedValue({
        reason: 'test',
      });

      const result = await service.getBanDetailsByUserId('user-1');

      expect(result.banDetails).toBeDefined();
    });
  });

  describe('changeUserRole', () => {
    it('should change user role', async () => {
      userRepositoryMock.findUserById.mockResolvedValue(baseUser);
      userRepositoryMock.updateUser.mockResolvedValue({
        ...baseUser,
        role: 'ADMIN',
      });

      const result = await service.changeUserRole({
        id: 'user-1',
        role: UserRole.ADMIN,
      });

      expect(result.role).toBe(UserRole.ADMIN);
    });
  });
});
