import { CommonModule } from '@angular/common';
import { ModuleWithProviders, NgModule, Optional } from '@angular/core';
import { AuthService, IUserInfo } from '@signature/webfrontauth';
import { IAuthenticationInfoTypeSystem } from '@signature/webfrontauth';
import { AxiosInstance } from 'axios';
import { AuthGuard } from './AuthGuard';
import { AuthServiceClientConfiguration } from './AuthServiceClientConfiguration';
import { AXIOS, WFA_TYPESYSTEM } from './injectionTokens';
import { NgxAuthService } from './NgxAuthService';

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
   * Returns the module with its providers.
   * Not for use in shared modules.
   */
  public static forRoot(): ModuleWithProviders<NgxAuthModule> {
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
        AuthGuard,
        NgxAuthService
      ]
    };
  }
}
