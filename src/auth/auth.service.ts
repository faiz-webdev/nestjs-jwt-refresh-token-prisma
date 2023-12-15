import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as bcrypt from 'bcrypt';
import { Tokens } from './types';

@Injectable()
export class AuthService {
  constructor(private readonly prisma: PrismaService) {}

  async hashedData(data: string) {
    return bcrypt.hash(data, 10);
  }

  async singupLocal(dto: AuthDto): Promise<Tokens> {
    const hash = await this.hashedData(dto.password);

    const newUser = await this.prisma.user.create({
      data: {
        email: dto.email,
        hash,
      },
    });
  }

  singinLocal() {}

  logout() {}

  refreshTokens() {}
}
