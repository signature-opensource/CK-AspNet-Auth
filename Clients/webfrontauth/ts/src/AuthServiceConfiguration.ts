import { IAuthServiceConfiguration, IEndPoint, ILocalStoragePersistence } from './authService.model.public';

export class AuthServiceConfiguration {
    private readonly _identityServerEndPoint: string;
    private readonly _localStoragePersistence: ILocalStoragePersistence;

    public get webFrontAuthEndPoint(): string { return this._identityServerEndPoint; }
    public get localStoragePersistence(): ILocalStoragePersistence { return this._localStoragePersistence; }

    constructor(config: IAuthServiceConfiguration) {
        this._identityServerEndPoint = AuthServiceConfiguration.getUrlFromEndPoint(config.identityEndPoint);
        this._localStoragePersistence = AuthServiceConfiguration.ensureLocalStoragePersistence(config.localStoragePersistence);
    }

    private static getUrlFromEndPoint(endPoint: IEndPoint): string {
        if (!endPoint.hostname) { return '/'; }
        const isHttps = !endPoint.disableSsl;
        const hostnameAndPort = endPoint.port !== undefined && endPoint.port !== null && !this.isDefaultPort(isHttps, endPoint.port)
            ? `${endPoint.hostname}:${endPoint.port}`
            : `${endPoint.hostname}`;

        return hostnameAndPort
            ? `${isHttps ? 'https' : 'http'}://${hostnameAndPort}/`
            : '/';
    }

    private static isDefaultPort(isHttps: boolean, portNumber: number): boolean {
        return isHttps ? portNumber === 443 : portNumber === 80;
    }

    private static ensureLocalStoragePersistence(localStoragePersistence?: ILocalStoragePersistence): ILocalStoragePersistence {
        return this.storageAvailable('localStorage')
            ? localStoragePersistence || { onBasicLogin: true, onRefresh: true, onStartLogin: true, onUnsafeDirectLogin: true }
            : { onBasicLogin: false, onRefresh: false, onStartLogin: false, onUnsafeDirectLogin: false };
    }

    /**
     * Detects whether the localStorage is available.
     * Reference: https://developer.mozilla.org/en-US/docs/Web/API/Web_Storage_API/Using_the_Web_Storage_API#Feature-detecting_localStorage
     * @param storageType Storage type, either 'localStorage' or 'sessionStorage'
     */
    private static storageAvailable(storageType: 'localStorage' | 'sessionStorage'): boolean {
        let storage: Storage;
        try {
            if (typeof (window) === 'undefined')
                return false;

            storage = window[storageType];
            const key = '__storage_test__';
            storage.setItem(key, key);
            storage.removeItem(key);
            return true;
        }
        catch (e) {
            return e instanceof DOMException
                && (e.code === 22 || e.code === 1014 || e.name === 'QuotaExceededError' || e.name === 'NS_ERROR_DOM_QUOTA_REACHED')
                && (storage && storage.length !== 0);
        }
    }
}
