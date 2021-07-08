import { IAuthServiceConfiguration, IEndPoint, IAuthenticationInfo, IUserInfo } from './authService.model.public';

export class AuthServiceConfiguration {
    private readonly _identityServerEndPoint: string;

    /** When defined, the local storage is available. */
    public readonly localStorage?: Storage;

    /** Gets the end point address. */
    public get webFrontAuthEndPoint(): string { return this._identityServerEndPoint; }

    constructor(config: IAuthServiceConfiguration) {
        this._identityServerEndPoint = AuthServiceConfiguration.getUrlFromEndPoint(config.identityEndPoint);
        if(  config.useLocalStorage ) this.localStorage = this.getAvailableStorage('localStorage');
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

    /**
     * Returns the localStorage or null if it is unavailable.
     * Reference: https://developer.mozilla.org/en-US/docs/Web/API/Web_Storage_API/Using_the_Web_Storage_API#Feature-detecting_localStorage
     * @param storageType Storage type, either 'localStorage' or 'sessionStorage'
     */
    private getAvailableStorage(storageType: 'localStorage' | 'sessionStorage'):  Storage|undefined {
        let storage: Storage|undefined = undefined;
        try {
            if (typeof (window) !== 'undefined') {
                storage = window[storageType];
                const key = '__storage_test__';
                storage.setItem(key, key);
                storage.removeItem(key);
            }
        }
        catch (e) {
            const isAvailable = e instanceof DOMException 
                                && ( 
                                        // everything except Firefox
                                        e.code === 22 ||
                                        // Firefox
                                        e.code === 1014 ||
                                        // test name field too, because code might not be present
                                        // everything except Firefox
                                        e.name === 'QuotaExceededError' ||
                                        // Firefox
                                        e.name === 'NS_ERROR_DOM_QUOTA_REACHED'
                                    )
                                   // acknowledge QuotaExceededError only if there's something already stored
                                && (storage && storage!.length !== 0);
            
            if( !isAvailable ) storage = undefined;
        }
        return storage;
    }

}
