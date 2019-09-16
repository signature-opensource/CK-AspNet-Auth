import { NgModule, ModuleWithProviders, APP_INITIALIZER } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HTTP_INTERCEPTORS } from '@angular/common/http';
import { AuthService, IUserInfo } from '@signature/webfrontauth';

import { AuthInterceptor } from './AuthInterceptor';
import { AuthGuard } from './AuthGuard';
import { NgxAuthService } from './NgxAuthService';
import { AuthServiceClientConfiguration } from './AuthServiceClientConfiguration';
import { IAuthenticationInfoTypeSystem } from '@signature/webfrontauth/src/type-system';
import { AxiosInstance } from 'axios';

export function authServiceFactory(
  authConfig: AuthServiceClientConfiguration,
  axiosInstance: AxiosInstance,
  typeSystem: IAuthenticationInfoTypeSystem<IUserInfo>
): AuthService {
  return new AuthService(authConfig, axiosInstance, typeSystem);
}

export async function initializeAuthAsync(
  authService: AuthService
): Promise<void> {
  console.log('Refreshing authentication...');
  await authService.refresh(true, true);
}

export function initializeAuthFactory(
  authService: AuthService
): () => Promise<void> {
  const f = () => initializeAuthAsync(authService);
  // Do not return the lambda directly, or ngc will fail to AOT with a
  // `Lambda not supported` error.
  return f;
}

/**
 * Core Angular WebFrontAuth authentication modules.
 * REQUIRES THE FOLLOWING INJECTIONS:
 * - AuthServiceClientConfiguration
 * - AxiosInstance
 * - IAuthenticationInfoTypeSystem<IUserInfo>
 * @export
 */
@NgModule({
  imports: [CommonModule]
})
export class NgxAuthModule {
  public static forRoot(): ModuleWithProviders {
    return {
      ngModule: NgxAuthModule,
      providers: [
        {
          provide: AuthService,
          useFactory: authServiceFactory,
          deps: [
            AuthServiceClientConfiguration,
            'AxiosInstance', // Manual injection
            'IAuthenticationInfoTypeSystem' // Manual injection
          ]
        },
        {
          provide: HTTP_INTERCEPTORS,
          useClass: AuthInterceptor,
          multi: true
        },
        {
          provide: APP_INITIALIZER,
          useFactory: initializeAuthFactory,
          multi: true,
          deps: [AuthService]
        },
        AuthGuard,
        NgxAuthService
      ]
    };
  }
}
