import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService
  extends PrismaClient
  implements OnModuleInit, OnModuleDestroy
{
  constructor(config: ConfigService) {
    const url = config.get<string>('DATABASE_URL');
    super({
      datasources: {
        db: {
          //   url: 'postgresql://postgres:root@localhost:5432/nestjs_prisma_refresh_token?schema=public',
          url,
        },
      },
    });
  }

  async onModuleInit() {
    await this.$connect();
  }

  async onModuleDestroy() {
    await this.$disconnect();
  }

  async cleanDatabase() {
    console.log('clean database');
    // if (process.env.NODE_ENV === 'production') return;

    // teardown logic
    // return Promise.all([this.user.deleteMany()]);
  }
}
