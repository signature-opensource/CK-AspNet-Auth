import { IAuthServiceConfiguration, IEndPoint } from './authService.model.public';

export class AuthServiceConfiguration {
    private readonly _identityServerEndPoint: string;
    
    public get webFrontAuthEndPoint(): string { return this._identityServerEndPoint; }
    
    constructor(config: IAuthServiceConfiguration) {
        this._identityServerEndPoint = this.getUrlFromEndPoint(config.identityEndPoint);
    }

    private getUrlFromEndPoint(endPoint: IEndPoint): string {
        if(!endPoint.hostname) { return '/'; }

        const hostname = endPoint.port !== undefined && endPoint.port !== null
            ? `${endPoint.hostname}:${endPoint.port}`
            : `${endPoint.hostname}`;

        const disableSsl: boolean = endPoint.disableSsl ? endPoint.disableSsl : false;
        
        return hostname
            ? `${disableSsl ? 'http' : 'https'}://${hostname}/`
            : '/';
    }
}
