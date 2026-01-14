import { NestFactory } from '@nestjs/core';
import { Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { MicroserviceOptions, Transport } from '@nestjs/microservices';

import { AppModule } from './app.module';
import { HEALTH_CHECK_V1_PACKAGE_NAME } from './generated-types/health-check';
import { GrpcExceptionFilter } from './utils/filters/grpc-exception.filter';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  const logger = new Logger('Main');
  const configService = app.get(ConfigService);
  const url = configService.getOrThrow<string>('TRANSPORT_URL');

  app.useGlobalFilters(new GrpcExceptionFilter());

  app.connectMicroservice<MicroserviceOptions>({
    transport: Transport.GRPC,
    options: {
      package: [HEALTH_CHECK_V1_PACKAGE_NAME],
      protoPath: ['proto/health-check.proto'],
      url,
    },
  });

  await app.startAllMicroservices();
  await app.init();
  logger.log('User microservice is running on ' + url);
}
void bootstrap();
