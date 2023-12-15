import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';
import { Tokens } from './types';
import { AuthGuard } from '@nestjs/passport';
import { Request } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('/local/signup')
  @HttpCode(HttpStatus.CREATED)
  singupLocal(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.singupLocal(dto);
  }

  @Post('/local/signin')
  @HttpCode(HttpStatus.OK)
  singinLocal(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.singinLocal(dto);
  }

  @UseGuards(AuthGuard('jwt'))
  @Post('/logout')
  @HttpCode(HttpStatus.OK)
  logout(@Req() req: Request) {
    this.authService.logout(req.user['id']);
  }

  @UseGuards(AuthGuard('jwt-refresh'))
  @Post('/refresh')
  @HttpCode(HttpStatus.OK)
  refreshTokens() {
    this.authService.refreshTokens();
  }
}
