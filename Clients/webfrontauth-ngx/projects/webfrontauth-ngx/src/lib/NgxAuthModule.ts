import { NgModule, ModuleWithProviders, APP_INITIALIZER, Optional } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HTTP_INTERCEPTORS } from '@angular/common/http';
import { AuthService, IUserInfo } from '@signature/webfrontauth';
import { AuthInterceptor } from './AuthInterceptor';
import { AuthGuard } from './AuthGuard';
import { NgxAuthService } from './NgxAuthService';
import { AuthServiceClientConfiguration } from './AuthServiceClientConfiguration';
import { IAuthenticationInfoTypeSystem } from '@signature/webfrontauth/src/type-system';
import { AxiosInstance } from 'axios';
import { AXIOS, WFA_TYPESYSTEM } from './injectionTokens';

export function authServiceFactory(
  authConfig: AuthServiceClientConfiguration,
  axiosInstance: AxiosInstance,
  typeSystem?: IAuthenticationInfoTypeSystem<IUserInfo>
): AuthService {
  return new AuthService(authConfig, axiosInstance, typeSystem);
}

export function initializeAuthFactory(
  authService: AuthService
): () => Promise<void> {
  const f = () => authService.refresh(true, true, true);
  // Do not return the lambda directly, or ngc will fail to AOT with a
  // `Lambda not supported` error.
  return f;
}

/**
 * WebFrontAuth authentication module for Angular.
 * Requires pre-bootstrap injection of AuthServiceClientConfiguration and AXIOS.
 * Supports optional injection of WFA_TYPESYSTEM.
 *
 * @description Automatically refreshes authentication on init, and authenticates Angular's HttpClient.
 * @export
 */
@NgModule({
  imports: [CommonModule]
})
export class NgxAuthModule {
  /**
   * Returns the module with its providers, and registers its own classes
   * into HTTP_INTERCEPTORS and APP_INITIALIZER.
   * Not for use in shared modules.
   */
  public static forRoot(): ModuleWithProviders {
    return {
      ngModule: NgxAuthModule,
      providers: [
        {
          provide: AuthService,
          useFactory: authServiceFactory,
          deps: [
            AuthServiceClientConfiguration, // Injection from pre-bootstrap
            AXIOS, // Injection from pre-bootstrap
            [new Optional(), WFA_TYPESYSTEM], // Optional injection from pre-bootstrap
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
