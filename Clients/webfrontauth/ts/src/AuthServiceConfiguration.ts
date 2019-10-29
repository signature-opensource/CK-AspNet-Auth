import { IAuthServiceConfiguration, IEndPoint } from './authService.model.public';

export class AuthServiceConfiguration {
    private readonly _identityServerEndPoint: string;

    public get webFrontAuthEndPoint(): string { return this._identityServerEndPoint; }

    constructor(config: IAuthServiceConfiguration) {
        this._identityServerEndPoint = this.getUrlFromEndPoint(config.identityEndPoint);
    }

    private getUrlFromEndPoint(endPoint: IEndPoint): string {
        if (!endPoint.hostname) { return '/'; }
        const isHttps = !endPoint.disableSsl;
        const hostnameAndPort = endPoint.port !== undefined && endPoint.port !== null && !this.isDefaultPort(isHttps, endPoint.port)
            ? `${endPoint.hostname}:${endPoint.port}`
            : `${endPoint.hostname}`;

        return hostnameAndPort
            ? `${isHttps ? 'https' : 'http'}://${hostnameAndPort}/`
            : '/';
    }

    private isDefaultPort(isHttps: boolean, portNumber: number): boolean {
        return isHttps ? portNumber === 443 : portNumber === 80;
    }
}
