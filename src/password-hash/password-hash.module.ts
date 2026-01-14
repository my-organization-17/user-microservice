import { Module } from '@nestjs/common';
import { PasswordHashService } from './password-hash.service';

@Module({
  controllers: [],
  providers: [PasswordHashService],
  exports: [PasswordHashService],
})
export class PasswordHashModule {}
