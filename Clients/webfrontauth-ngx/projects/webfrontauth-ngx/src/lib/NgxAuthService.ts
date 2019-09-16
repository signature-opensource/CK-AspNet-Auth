import { Injectable } from '@angular/core';
import { IUserInfo, AuthService, IAuthenticationInfo } from '@signature/webfrontauth';
import { Observable, BehaviorSubject } from 'rxjs';
import { NgxAuthModule } from './NgxAuthModule';

@Injectable({ providedIn: NgxAuthModule })
export class NgxAuthService<T extends IUserInfo = IUserInfo> {
  constructor(private authService: AuthService<T>) {
    this.authService.addOnChange(() => {
      this._authenticationInfo$.next(this.authService.authenticationInfo);
    });
    this._authenticationInfo$.next(this.authService.authenticationInfo);
  }

  private readonly _authenticationInfo$: BehaviorSubject<IAuthenticationInfo<T>>
    = new BehaviorSubject(undefined);
  public readonly authenticationInfo$: Observable<IAuthenticationInfo<T>>
    = this._authenticationInfo$.asObservable();
}
