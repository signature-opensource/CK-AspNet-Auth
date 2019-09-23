import { CanActivate, ActivatedRouteSnapshot, RouterStateSnapshot, CanActivateChild } from '@angular/router';
import { AuthService } from '@signature/webfrontauth';
import { Observable } from 'rxjs';

export abstract class AuthSchemeGuard implements CanActivate, CanActivateChild {

  /**
   * If defined, the scheme must be contained in the array to activate the route
   */
  protected abstract authorizedSchemes: string[];

  /**
   * If defined, the scheme must not be contained in the array to activate the route
   */
  protected abstract blockedSchemes: string[];

  constructor(private readonly authService: AuthService) { }

  public canActivate(
    route: ActivatedRouteSnapshot,
    state: RouterStateSnapshot
  ): Observable<boolean> | Promise<boolean> | boolean {

    const current = this.authService.authenticationInfo.user.schemes;
    const latest = current.reduce((a, b) => a.lastUsed < b.lastUsed ? a : b);

    if (this.blockedSchemes && this.blockedSchemes.length > 0
      && this.blockedSchemes.includes(latest.name)) {
      return false;
    }

    if (this.authorizedSchemes && this.authorizedSchemes.length > 0
      && !this.authorizedSchemes.includes(latest.name)) {
      return false;
    }

    return true;
  }

  public canActivateChild(
    route: ActivatedRouteSnapshot,
    state: RouterStateSnapshot
  ): Observable<boolean> | Promise<boolean> | boolean {
    return this.canActivate(route, state);
  }
}
