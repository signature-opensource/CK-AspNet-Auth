import { IAuthServiceConfiguration, IEndPoint, ILocalStoragePersistence } from './authService.model.public';

export class AuthServiceConfiguration {
    private readonly _identityServerEndPoint: string;
    private readonly _localStoragePersistence: ILocalStoragePersistence;

    public get webFrontAuthEndPoint(): string { return this._identityServerEndPoint; }
    public get localStoragePersistence(): ILocalStoragePersistence { return this._localStoragePersistence; }

    constructor(config: IAuthServiceConfiguration) {
        this._identityServerEndPoint = this.getUrlFromEndPoint(config.identityEndPoint);
        this._localStoragePersistence = this.ensureLocalStoragePersistence(config.localStoragePersistence);
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

    private ensureLocalStoragePersistence(localStoragePersistence: ILocalStoragePersistence): ILocalStoragePersistence {
        if (!!localStoragePersistence) {
            const { onBasicLogin, onRefresh, onStartLogin, onUnsafeDirectLogin } = localStoragePersistence;
            if (!(onBasicLogin || onRefresh || onStartLogin || onUnsafeDirectLogin)) { return localStoragePersistence; }
        }

        if (!(typeof (window) !== 'undefined' && window.localStorage)) {
            return { onBasicLogin: false, onRefresh: false, onStartLogin: false, onUnsafeDirectLogin: false };
        }

        return localStoragePersistence || { onBasicLogin: true, onRefresh: true, onStartLogin: true, onUnsafeDirectLogin: true };
    }
}
