import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';
import { Tokens } from './types';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('/local/signup')
  singupLocal(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.singupLocal(dto);
  }

  @Post('/local/signin')
  singinLocal(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.singinLocal(dto);
  }

  @Post('/logout')
  logout() {
    this.authService.logout();
  }

  @Post('/refresh')
  refreshTokens() {
    this.authService.refreshTokens();
  }
}
