import { IAuthServiceConfiguration, IEndPoint } from '@signature/webfrontauth';

/**
 * WebFrontAuth configuration class.
 *
 * @export
 */
export class AuthServiceClientConfiguration implements IAuthServiceConfiguration {
  /**
   * Creates an instance of AuthServiceClientConfiguration using the provided login route and endpoint.
   * @param identityEndPoint The identity endpoint to use in WebFrontAuth
   * @param [loginPath='/login'] The route path WebFrontAuth should redirect to when authentication is required.
   */
  constructor(
    public readonly identityEndPoint: IEndPoint,
    public readonly loginPath: string = '/login'
  ) {
    this.loginPath = loginPath;
    this.identityEndPoint = identityEndPoint;
  }
}

/**
 * Creates an instance of AuthServiceClientConfiguration using the specified login route,
 * and the current host as identity endpoint.
 *
 * @export
 * @param [loginPath='/login'] The route path WebFrontAuth should redirect to when authentication is required.
 */
export function createAuthConfigUsingCurrentHost(
  loginPath: string = '/login'
): AuthServiceClientConfiguration {
  const isHttps = window.location.protocol.toLowerCase() === 'https:';
  const identityEndPoint: IEndPoint = {
    hostname: window.location.hostname,
    port: window.location.port
      ? Number(window.location.port)
      : isHttps
        ? 443
        : 80,
    disableSsl: !isHttps
  };
  return new AuthServiceClientConfiguration(identityEndPoint, loginPath);
}
