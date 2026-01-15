import { IsNotEmpty, IsNumber, IsPositive, IsString } from 'class-validator';

export class EnvironmentVariables {
  @IsString()
  @IsNotEmpty()
  readonly TRANSPORT_URL: string;

  @IsString()
  @IsNotEmpty()
  readonly DATABASE_URL: string;

  @IsString()
  @IsNotEmpty()
  readonly JWT_ACCESS_SECRET: string;

  @IsString()
  @IsNotEmpty()
  readonly JWT_REFRESH_SECRET: string;

  @IsNumber()
  @IsNotEmpty()
  @IsPositive()
  readonly JWT_ACCESS_EXPIRATION: number;

  @IsNumber()
  @IsNotEmpty()
  @IsPositive()
  readonly JWT_REFRESH_EXPIRATION: number;
}
