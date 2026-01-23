import { Test, TestingModule } from '@nestjs/testing';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

import { HashService } from 'src/hash/hash.service';
import { RedisService } from 'src/redis/redis.service';
import { UserRole } from 'src/generated-types/user';
import { TokenService } from '../token.service';

describe('TokenService', () => {
  let service: TokenService;

  const jwtServiceMock = {
    signAsync: jest.fn(),
    verifyAsync: jest.fn(),
  };

  const configServiceMock = {
    get: jest.fn(),
    getOrThrow: jest.fn(),
  };

  const hashServiceMock = {
    create: jest.fn(),
  };

  const redisServiceMock = {
    set: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        TokenService,
        { provide: JwtService, useValue: jwtServiceMock },
        { provide: ConfigService, useValue: configServiceMock },
        { provide: HashService, useValue: hashServiceMock },
        { provide: RedisService, useValue: redisServiceMock },
      ],
    }).compile();

    service = module.get<TokenService>(TokenService);

    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('refreshKey', () => {
    it('should build correct redis key', () => {
      const key = service.refreshKey('user123', 'session456');
      expect(key).toBe('refresh:user123:session456');
    });
  });

  describe('verifyJwtToken', () => {
    it('should verify access token with access secret', async () => {
      configServiceMock.get.mockReturnValue('access-secret');
      jwtServiceMock.verifyAsync.mockResolvedValue({ sub: 'user123' });

      const result = await service.verifyJwtToken<{ sub: string }>('token', true);

      expect(jwtServiceMock.verifyAsync).toHaveBeenCalledWith('token', {
        secret: 'access-secret',
      });
      expect(result.sub).toBe('user123');
    });

    it('should verify refresh token with refresh secret', async () => {
      configServiceMock.get.mockReturnValue('refresh-secret');
      jwtServiceMock.verifyAsync.mockResolvedValue({ sub: 'user123' });

      await service.verifyJwtToken('token', false);

      expect(jwtServiceMock.verifyAsync).toHaveBeenCalledWith('token', {
        secret: 'refresh-secret',
      });
    });
  });

  describe('generateJwtTokens', () => {
    it('should generate tokens, hash refresh token and store it in redis', async () => {
      jwtServiceMock.signAsync.mockResolvedValueOnce('access-token').mockResolvedValueOnce('refresh-token');

      hashServiceMock.create.mockResolvedValue('hashed-refresh-token');

      configServiceMock.get.mockImplementation((key: string) => {
        switch (key) {
          case 'JWT_ACCESS_SECRET':
            return 'access-secret';
          case 'JWT_REFRESH_SECRET':
            return 'refresh-secret';
          case 'JWT_ACCESS_EXPIRATION':
            return 900;
          case 'JWT_REFRESH_EXPIRATION':
            return 604800;
        }
      });

      configServiceMock.getOrThrow.mockReturnValue(604800);

      const result = await service.generateJwtTokens({
        userId: 'user123',
        isBanned: false,
        role: UserRole.USER,
        sid: 'sid123',
      });

      expect(jwtServiceMock.signAsync).toHaveBeenCalledTimes(2);

      expect(hashServiceMock.create).toHaveBeenCalledWith('refresh-token');

      expect(redisServiceMock.set).toHaveBeenCalledWith('refresh:user123:sid123', 'hashed-refresh-token', 'EX', 604800);

      expect(result).toEqual({
        accessToken: 'access-token',
        refreshToken: 'refresh-token',
      });
    });
  });
});
