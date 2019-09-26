import { Injectable } from '@angular/core';
import { ActivatedRouteSnapshot, CanActivate, RouterStateSnapshot, Router, CanActivateChild } from '@angular/router';
import { AuthService, AuthLevel } from '@signature/webfrontauth';
import { AuthServiceClientConfiguration } from './AuthServiceClientConfiguration';

@Injectable({ providedIn: 'root' }) // Service is provided in forRoot().
export class AuthGuard implements CanActivate, CanActivateChild {

  constructor(
    private readonly router: Router,
    private readonly authService: AuthService,
    private readonly authConfig: AuthServiceClientConfiguration
  ) {
  }

  public canActivate(route: ActivatedRouteSnapshot, state: RouterStateSnapshot): boolean {
    if (this.authService.authenticationInfo.level >= AuthLevel.Normal) { return true; }
    this.router.navigate([this.authConfig.loginPath], { queryParams: { returnUrl: state.url } });
    return false;
  }

  public canActivateChild(childRoute: ActivatedRouteSnapshot, state: RouterStateSnapshot): boolean {
    return this.canActivate(childRoute, state);
  }
}
