import { IsNotEmpty, IsString } from 'class-validator';

export class EnvironmentVariables {
  @IsString()
  @IsNotEmpty()
  readonly TRANSPORT_URL: string;

  @IsString()
  @IsNotEmpty()
  readonly DATABASE_URL: string;
}
