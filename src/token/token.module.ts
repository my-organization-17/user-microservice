import { Module } from '@nestjs/common';

import { HashService } from 'src/hash/hash.service';
import { RedisService } from 'src/redis/redis.service';
import { TokenService } from './token.service';

@Module({
  imports: [],
  controllers: [],
  providers: [HashService, RedisService, TokenService],
})
export class TokenModule {}
