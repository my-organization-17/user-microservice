import { ConfigService } from '@nestjs/config';

jest.mock('@prisma/adapter-pg', () => ({
  PrismaPg: jest.fn().mockImplementation(() => ({ __brand: 'PrismaPgAdapter' })),
}));

jest.mock('prisma/generated-types/client', () => ({
  PrismaClient: class MockPrismaClient {
    constructor() {}
  },
}));

import { PrismaService } from '../prisma.service';

describe('PrismaService', () => {
  const configServiceMock = {
    getOrThrow: jest.fn(),
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    configServiceMock.getOrThrow.mockReturnValue('postgresql://localhost:5432/testdb');

    const service = new PrismaService(configServiceMock as unknown as ConfigService);

    expect(service).toBeDefined();
  });

  it('should call configService.getOrThrow with DATABASE_URL', () => {
    configServiceMock.getOrThrow.mockReturnValue('postgresql://localhost:5432/testdb');

    new PrismaService(configServiceMock as unknown as ConfigService);

    expect(configServiceMock.getOrThrow).toHaveBeenCalledWith('DATABASE_URL');
  });

  it('should throw error if DATABASE_URL is empty string', () => {
    configServiceMock.getOrThrow.mockReturnValue('');

    expect(() => new PrismaService(configServiceMock as unknown as ConfigService)).toThrow(
      'DATABASE_URL is not defined in the environment variables',
    );
  });

  it('should be an instance of PrismaService', () => {
    configServiceMock.getOrThrow.mockReturnValue('postgresql://localhost:5432/testdb');

    const service = new PrismaService(configServiceMock as unknown as ConfigService);

    expect(service).toBeInstanceOf(PrismaService);
  });
});
