import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaPg } from '@prisma/adapter-pg';

import { PrismaClient } from 'prisma/generated-types/client';

@Injectable()
export class PrismaService extends PrismaClient {
  private readonly logger = new Logger(PrismaService.name);
  constructor(configService: ConfigService) {
    const databaseUrl = configService.getOrThrow<string>('DATABASE_URL');

    if (!databaseUrl) {
      throw new Error('DATABASE_URL is not defined in the environment variables');
    }
    const adapter = new PrismaPg({
      connectionString: databaseUrl,
    });
    super({ adapter });
    this.logger.log('PrismaService initialized with PostgreSQL adapter');
  }
}
