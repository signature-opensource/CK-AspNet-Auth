import { IAuthServiceConfiguration, IEndPoint } from '@signature/webfrontauth';

export class AuthServiceClientConfiguration
  implements IAuthServiceConfiguration {
  /**
   * The route to the page used to log in.
   * A query parameter called `returnUrl` is automatically provided.
   */
  public loginPath = '/login';

  /**
   * The configured identity endpoint.
   */
  public identityEndPoint: IEndPoint;

  /**
   * Creates an instance of AuthServiceClientConfiguration using the provided login route and endpoint.
   */
  constructor(loginPath: string, identityEndPoint: IEndPoint) {
    const isHttps = window.location.protocol.toLowerCase() === 'https:';

    this.loginPath = loginPath;
    this.identityEndPoint = {
      hostname: window.location.hostname,
      port: window.location.port
        ? Number(window.location.port)
        : isHttps
        ? 443
        : 80,
      disableSsl: !isHttps
    };
  }
}

/**
 * Creates an instance of AuthServiceClientConfiguration using the specified login route,
 * and the current host as identity endpoint.
 */
export function createAuthConfigUsingCurrentHost(
  loginPath: string
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
  return new AuthServiceClientConfiguration(loginPath, identityEndPoint);
}
