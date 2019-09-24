import { Injectable } from '@angular/core';
import { IUserInfo, AuthService, IAuthenticationInfo } from '@signature/webfrontauth';
import { Observable, BehaviorSubject } from 'rxjs';

/**
 * WebFrontAuth utility service for Angular.
 *
 * @description Exposes the current IAuthenticationInfo as an Observable, and the injected AuthService.
 * @export
 */
@Injectable({ providedIn: 'root' }) // Service is provided in forRoot().
export class NgxAuthService<T extends IUserInfo = IUserInfo> {
  private readonly _authenticationInfo: BehaviorSubject<IAuthenticationInfo<T>>;

  /**
   * An Observable emitting the current IAuthenticationInfo, and any new ones.
   */
  public readonly authenticationInfo$: Observable<IAuthenticationInfo<T>>;

  constructor(public readonly authService: AuthService<T>) {
    this._authenticationInfo = new BehaviorSubject(this.authService.authenticationInfo);
    this.authenticationInfo$ = this._authenticationInfo.asObservable();

    // Register on change event
    this.authService.addOnChange(source => this._authenticationInfo.next(source.authenticationInfo));
  }
}
