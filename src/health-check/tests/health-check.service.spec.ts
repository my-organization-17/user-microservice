import { Test, TestingModule } from '@nestjs/testing';
import { HealthCheckService } from '../health-check.service';
import { PrismaService } from 'src/prisma/prisma.service';

describe('HealthCheckService', () => {
  let service: HealthCheckService;
  let prisma: jest.Mocked<PrismaService>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        HealthCheckService,
        {
          provide: PrismaService,
          useValue: {
            $queryRaw: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<HealthCheckService>(HealthCheckService);
    prisma = module.get(PrismaService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('checkDatabaseConnection', () => {
    it('should return true when database is reachable', async () => {
      prisma.$queryRaw.mockResolvedValueOnce(1 as any);

      const result = await service.checkDatabaseConnection();

      expect(prisma.$queryRaw).toHaveBeenCalled();
      expect(result).toBe(true);
    });

    it('should return false when database throws error', async () => {
      prisma.$queryRaw.mockRejectedValueOnce(new Error('DB down'));

      const result = await service.checkDatabaseConnection();

      expect(prisma.$queryRaw).toHaveBeenCalled();
      expect(result).toBe(false);
    });
  });
});
