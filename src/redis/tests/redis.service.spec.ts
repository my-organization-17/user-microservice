import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';

import { RedisService } from '../redis.service';

describe('RedisService', () => {
  let service: RedisService;

  const configServiceMock = {
    getOrThrow: jest.fn(),
  };

  jest.mock('ioredis', () => {
    return jest.fn().mockImplementation(() => ({
      on: jest.fn(),
      ping: jest.fn(),
      quit: jest.fn(),
    }));
  });

  beforeEach(async () => {
    configServiceMock.getOrThrow.mockImplementation((key: string) => {
      switch (key) {
        case 'REDIS_HOST':
          return 'localhost';
        case 'REDIS_PORT':
          return 6379;
      }
    });

    const module: TestingModule = await Test.createTestingModule({
      providers: [RedisService, { provide: ConfigService, useValue: configServiceMock }],
    }).compile();

    service = module.get<RedisService>(RedisService);

    jest.clearAllMocks();
  });

  afterAll(async () => {
    await service.quit();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
