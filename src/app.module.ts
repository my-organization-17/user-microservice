import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';

import { validateEnv } from './utils/validators/env-validator';
import { EnvironmentVariables } from './utils/env.dto';
import { PrismaModule } from './prisma/prisma.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: ['.env.local'],
      validate: (config) => validateEnv(config, EnvironmentVariables),
    }),
    PrismaModule,
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
