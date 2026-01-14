import { Injectable, Logger } from '@nestjs/common';

import { PasswordHashService } from 'src/password-hash/password-hash.service';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly passwordHashService: PasswordHashService,
  ) {}
  protected readonly logger = new Logger(AuthService.name);
}
