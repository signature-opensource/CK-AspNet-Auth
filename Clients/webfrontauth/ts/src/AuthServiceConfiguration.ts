import { IAuthServiceConfiguration, IEndPoint } from './authService.model.public';

function isDefaultPort(isHttps: boolean, portNumber: number) {
  if(isHttps) {
    return portNumber === 443;
  } else {
    return portNumber === 80;
  }
}

export class AuthServiceConfiguration {
    private readonly _identityServerEndPoint: string;

    public get webFrontAuthEndPoint(): string { return this._identityServerEndPoint; }

    constructor(config: IAuthServiceConfiguration) {
        this._identityServerEndPoint = this.getUrlFromEndPoint(config.identityEndPoint);
    }

    private getUrlFromEndPoint(endPoint: IEndPoint): string {
        if(!endPoint.hostname) { return '/'; }
        const isHttps = !endPoint.disableSsl;
        const hostnameAndPort = endPoint.port !== undefined
          && endPoint.port !== null
          && !isDefaultPort( isHttps, endPoint.port )
            ? `${endPoint.hostname}:${endPoint.port}`
            : `${endPoint.hostname}`;

        return hostnameAndPort
            ? `${isHttps ? 'https' : 'http'}://${hostnameAndPort}/`
            : '/';
    }
}
