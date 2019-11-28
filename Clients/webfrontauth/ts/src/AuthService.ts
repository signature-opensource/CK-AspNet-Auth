import { AxiosRequestConfig, AxiosError, AxiosInstance } from 'axios';

import { IAuthenticationInfo, IUserInfo, IAuthServiceConfiguration, IWebFrontAuthError } from './index';
import { IAuthenticationInfoTypeSystem, StdAuthenticationTypeSystem, PopupDescriptor, IAuthenticationInfoImpl, WebFrontAuthError } from './index.extension';
import { IWebFrontAuthResponse, AuthServiceConfiguration } from './index.private';

export class AuthService<T extends IUserInfo = IUserInfo> {

    private _authenticationInfo: IAuthenticationInfoImpl<T>;
    private _token: string;
    private _refreshable: boolean;
    private _availableSchemes: ReadonlyArray<string>;
    private _version: string;
    private _configuration: AuthServiceConfiguration;    
    private _currentError?: IWebFrontAuthError;

    private _axiosInstance: AxiosInstance;
    private _typeSystem: IAuthenticationInfoTypeSystem<T>;
    private _popupDescriptor: PopupDescriptor;

    private _expTimer;
    private _cexpTimer;

    private _subscribers: Set<(eventSource: AuthService) => void>;

    /** Gets the current authentication information. */
    public get authenticationInfo(): IAuthenticationInfo<T> { return this._authenticationInfo; }
    /** Gets the current authentication token. This is the empty string when there is currently no authentication. */
    public get token(): string { return this._token; }
    /** Gets whether this service will automatically refreshes the authentication. */
    public get refreshable(): boolean { return this._refreshable; }
    /** Gets the available authentication schemes names. */
    public get availableSchemes(): ReadonlyArray<string> { return this._availableSchemes; }
    /** Gets the Authentication server version. */
    public get version(): string { return this._version; }
    /** Gets the current error if any. */
    public get currentError(): IWebFrontAuthError|undefined { return this._currentError; }

    public get popupDescriptor(): PopupDescriptor {
        if (!this._popupDescriptor) { this._popupDescriptor = new PopupDescriptor(); }
        return this._popupDescriptor;
    }
    public set popupDescriptor(popupDescriptor: PopupDescriptor) {
        if (popupDescriptor) { this._popupDescriptor = popupDescriptor; }
    };

    //#region constructor

    constructor(
        configuration: IAuthServiceConfiguration,
        axiosInstance: AxiosInstance,
        typeSystem?: IAuthenticationInfoTypeSystem<T>
    ) {
        if (!configuration) { throw new Error('Configuration must be defined.'); }
        this._configuration = new AuthServiceConfiguration(configuration);

        if (!axiosInstance) { throw new Error('AxiosInstance must be defined.'); }
        this._axiosInstance = axiosInstance;
        this._axiosInstance.interceptors.request.use(this.onIntercept());

        this._typeSystem = typeSystem ? typeSystem : new StdAuthenticationTypeSystem() as any;
        this._version = '';
        this._availableSchemes = [];
        this._subscribers = new Set<() => void>();
        this._expTimer = null;
        this._cexpTimer = null;

        if (!(typeof window === 'undefined')) {
            window.addEventListener('message', this.onMessage(), false);
        }

        this.localDisconnect();
    }

    public static async createAsync<T extends IUserInfo = IUserInfo>(
        configuration: IAuthServiceConfiguration,
        axiosInstance: AxiosInstance,
        typeSystem?: IAuthenticationInfoTypeSystem<T>,
        throwOnError: boolean = true
    ): Promise<AuthService> {
        const authService = new AuthService<T>(configuration, axiosInstance, typeSystem);
        try {
            await authService.refresh(true, true);
            if (authService.currentError) {
                console.error(
                    'Encountered error while refreshing.',
                    authService.currentError.errorId,
                    authService.currentError.errorReason
                );

                if (throwOnError) {
                    throw new Error('Setup did not complete successfully.');
                }
            }
            return authService;
        } catch (error) {
            console.error(error);
            return authService;
        }
    }

    //#endregion

    //#region events

    private readonly maxTimeout: number = 2147483647;

    private setExpirationTimeout(): void {
        const timeDifference = this._authenticationInfo.expires!.getTime() - Date.now()

        if (timeDifference > this.maxTimeout) {
            this._expTimer = setTimeout(this.setExpirationTimeout, this.maxTimeout);
        } else {
            this._expTimer = setTimeout(() => {
                if (this._refreshable) {
                    this.refresh();
                } else {
                    this._authenticationInfo = this._authenticationInfo.setExpires(undefined);
                    this.onChange();
                }
            }, timeDifference);
        }
    }

    private setCriticialExpirationTimeout(): void {
        const timeDifference = this._authenticationInfo.criticalExpires!.getTime() - Date.now()

        if (timeDifference > this.maxTimeout) {
            this._cexpTimer = setTimeout(this.setCriticialExpirationTimeout, this.maxTimeout);
        } else {
            this._cexpTimer = setTimeout(() => {
                if (this._refreshable) {
                    this.refresh();
                } else {
                    this._authenticationInfo = this._authenticationInfo.setCriticalExpires();
                    this.onChange();
                }
            }, timeDifference);
        }
    }

    private clearTimeouts(): void {
        if (this._expTimer !== null) {
            clearTimeout(this._expTimer);
            this._expTimer = null;
        }
        if (this._cexpTimer !== null) {
            clearTimeout(this._cexpTimer);
            this._cexpTimer = null;
        }
    }

    private onIntercept(): (value: AxiosRequestConfig) => AxiosRequestConfig | Promise<AxiosRequestConfig> {
        return (config: AxiosRequestConfig) => {
            if( this._token
                && config.url 
                && config.url.startsWith(this._configuration.webFrontAuthEndPoint) ) {
                    Object.assign(config.headers, { Authorization: `Bearer ${this._token}` });
            }
            return config;
        };
    }

    private onMessage(): (this: Window, ev: MessageEvent) => void {
        return (messageEvent) => {
            if (messageEvent.data.WFA === 'WFA') {
                const origin = messageEvent.origin + '/';
                if (origin !== this._configuration.webFrontAuthEndPoint) {
                    throw new Error(`Incorrect origin in postMessage. Expected '${this._configuration.webFrontAuthEndPoint}', but was '${origin}'`);
                }
                this.parseResponse(messageEvent.data.data);
            }
        };
    }

    //#endregion

    //#region request handling

    private async sendRequest(
        entryPoint: 'basicLogin' | 'unsafeDirectLogin' | 'refresh' | 'impersonate' | 'logout' | 'startLogin',
        requestOptions: { body?: object, queries?: Array<string | { key: string, value: string }> },
        skipResponseHandling: boolean = false
    ): Promise<void> {
        try {
            this.clearTimeouts(); // We clear timeouts beforehand to avoid concurent requests

            const query = requestOptions.queries && requestOptions.queries.length
                ? `?${requestOptions.queries.map(q => typeof q === 'string' ? q : `${q.key}=${q.value}`).join('&')}`
                : '';
            const response = await this._axiosInstance.post<IWebFrontAuthResponse>(
                `${this._configuration.webFrontAuthEndPoint}.webfront/c/${entryPoint}${query}`,
                !!requestOptions.body ? JSON.stringify(requestOptions.body) : {},
                { withCredentials: true });

            const status = response.status;
            if (status === 200 ) {
                if (!skipResponseHandling ) { this.parseResponse(response.data); }
            } else {
                this._currentError = new WebFrontAuthError({
                    errorId: `HTTP.Status.${status}`,
                    errorReason: 'Unhandled success status'
                });
                this.localDisconnect();
            }
        } catch (error) {

            const axiosError = error as AxiosError;
            if (!(axiosError && axiosError.response)) {
                // Connection issue.
                if( entryPoint !== 'impersonate' 
                    && entryPoint !== 'logout' ) {

                    const storage = this._configuration.useLocalStorage( entryPoint );
                    if( storage ) {
                        const [auth,schemes] = this._typeSystem.authenticationInfo.loadFromLocalStorage( storage, 
                                                                                        this._configuration.webFrontAuthEndPoint, 
                                                                                        this._availableSchemes );
                        if( auth )
                        {
                            this._availableSchemes = schemes;
                            this._currentError = undefined;
                            this.localDisconnect( auth );
                        }
                    }
                }

                this._currentError = new WebFrontAuthError({
                    errorId: 'HTTP.Status.408',
                    errorReason: 'No connection could be made'
                });
            } else {
                const errorResponse = axiosError.response;
                this._currentError = new WebFrontAuthError({
                    errorId: `HTTP.Status.${errorResponse.status}`,
                    errorReason: 'Server response error'
                });
            }
            if( this._currentError ) this.localDisconnect();
        }
    }

    private parseResponse(r: IWebFrontAuthResponse): void {
        if (!r) {
            this.localDisconnect();
            return;
        }

        this._currentError = undefined;

        if (r.loginFailureCode && r.loginFailureReason) {
            this._currentError = new WebFrontAuthError({
                loginFailureCode: r.loginFailureCode,
                loginFailureReason: r.loginFailureReason
            });
        }

        if (r.errorId && r.errorText) {
            this._currentError = new WebFrontAuthError({
                errorId: r.errorId,
                errorReason: r.errorText
            });
        }

        if (this._currentError) {
            this.localDisconnect();
            return;
        }

        if (r.version) { this._version = r.version; }
        if (r.schemes) { this._availableSchemes = r.schemes; }

        if (!r.info) {
            this.localDisconnect();
            return;
        }

        this._token = r.token ? r.token : '';
        this._refreshable = r.refreshable ? r.refreshable : false;
        
        const info = this._typeSystem.authenticationInfo.fromJson(r.info, this._availableSchemes);
        if( info ) this._authenticationInfo = info;
        else this._authenticationInfo = this._typeSystem.authenticationInfo.none;

        if (this._authenticationInfo.expires) {
            this.setExpirationTimeout();
            if (this._authenticationInfo.criticalExpires) { this.setCriticialExpirationTimeout(); }
        }
        if( this._configuration.localStorage )
        {
            this._typeSystem.authenticationInfo.saveToLocalStorage( 
                    this._configuration.localStorage, 
                    this._configuration.webFrontAuthEndPoint, 
                    this._authenticationInfo, 
                    this._availableSchemes );
            }
        this.onChange();
    }

    private localDisconnect( authInfo?: IAuthenticationInfoImpl<T> ): void {
        this._token = '';
        this._refreshable = false;
        this._authenticationInfo = authInfo || this._typeSystem.authenticationInfo.none;
        this.clearTimeouts();
        this.onChange();
    }

    //#endregion

    //#region webfrontauth protocol

    /**
     * Triggers a basic login with a user name and password.
     * @param userName The user name.
     * @param password The password to use.
     * @param userData Optional user data that the server may use.
     */
    public async basicLogin(userName: string, password: string, userData?: object): Promise<void> {
        await this.sendRequest('basicLogin', { body: { userName, password, userData } });
    }

    /**
     * Triggers a direct, unsafe login (this has to be explicitly allowed by the server).
     * @param provider The authentication scheme to use.
     * @param payload The object payload that contain any information required to authenticate with the scheme.
     */
    public async unsafeDirectLogin(provider: string, payload: object): Promise<void> {
        await this.sendRequest('unsafeDirectLogin', { body: { provider, payload } });
    }

    /**
     * Refreshes the current authentication.
     * @param full True to force a full refresh of the authentication: the server will 
     * challenge again the authentication against its backend.
     * @param requestSchemes True to force a refresh of the availableSchemes (this is automatically 
     * true when availableSchemes is empty). 
     * @param requestVersion True to force a refresh of the version (this is automatically 
     * true when version is the empty string).
     */
    public async refresh(full: boolean = false, requestSchemes: boolean = false, requestVersion: boolean = false): Promise<void> {
        const queries: string[] = [];
        if (full) { queries.push('full'); }
        if (requestSchemes || this._availableSchemes.length === 0 ) { queries.push('schemes'); }
        if (requestVersion || this._version === '') { queries.push('version'); }
        await this.sendRequest('refresh', { queries });
    }

    /**
     * Request an impersonation to a user. This may be honored or not by the server.
     * @param user The user into whom the currently authenticated user wants to be impersonated.
     */
    public async impersonate(user: string | number): Promise<void> {
        const requestOptions = { body: (typeof user === 'string') ? { userName: user } : { userId: user } };
        await this.sendRequest('impersonate', requestOptions);
    }

    /**
     * Revokes the current authentication.
     * @param full True to remove any way to remmember the current authentication (long term cookie, local storage, etc.)
     */
    public async logout(full: boolean = false): Promise<void> {
        this._token = '';
        await this.sendRequest('logout', { queries: full ? ['full'] : [] }, /* skipResponseHandling */ true);   
        if( full ) {
            if( this._configuration.localStorage ) {
                this._typeSystem.authenticationInfo.saveToLocalStorage( 
                    this._configuration.localStorage, 
                    this._configuration.webFrontAuthEndPoint,
                    null,
                    []
                     )
            }
        }    
        await this.refresh();
    }

    public async startInlineLogin(scheme: string, returnUrl: string, userData?: object): Promise<void> {
        if (!returnUrl) { throw new Error('returnUrl must be defined.'); }
        if (!(returnUrl.startsWith('http://') || returnUrl.startsWith('https://'))) {
            if (returnUrl.charAt(0) !== '/') { returnUrl = '/' + returnUrl; }
            returnUrl = document.location.origin + returnUrl;
        }
        const queries = [
            { key: 'scheme', value: scheme }, 
            { key: 'returnUrl', value: encodeURI(returnUrl) },
            { key: 'callerOrigin', value: encodeURI(document.location.origin) } ];

        await this.sendRequest('startLogin', { body: userData, queries });
    }

    public async startPopupLogin(scheme: string, userData?: object): Promise<void> {

        if (scheme === 'Basic') {
            const popup = window.open('about:blank', this.popupDescriptor.popupTitle, this.popupDescriptor.features);
            if( popup == null ) throw new Error( "Unable to open popup window." );

            popup.document.write(this.popupDescriptor.generateBasicHtml());
            const onClick = async () => {

                const usernameInput = popup!.document.getElementById('username-input') as HTMLInputElement;
                const passwordInput = popup!.document.getElementById('password-input') as HTMLInputElement;
                const errorDiv = popup!.document.getElementById('error-div') as HTMLInputElement;
                const loginData = { username: usernameInput.value, password: passwordInput.value };

                if (!(loginData.username && loginData.password)) {
                    errorDiv.innerHTML = this.popupDescriptor.basicMissingCredentialsError;
                    errorDiv.style.display = 'block';
                } else {
                    await this.basicLogin(loginData.username, loginData.password, userData);

                    if (this.authenticationInfo.level >= 2) {
                        popup!.close();
                    } else {
                        errorDiv.innerHTML = this.popupDescriptor.basicInvalidCredentialsError;
                        errorDiv.style.display = 'block';
                    }
                }
            }

            const eOnClick = popup.document.getElementById('submit-button'); 
            if( eOnClick == null ) throw new Error( "Unable to find required 'submit-button' element." );
            eOnClick.onclick = (async () => await onClick());
        } 
        else {
            const url = `${this._configuration.webFrontAuthEndPoint}.webfront/c/startLogin`;
            userData = { ...userData, callerOrigin: document.location.origin };
            const queryString = userData 
                                ? Object.keys(userData).map((key) => encodeURIComponent(key) + '=' + encodeURIComponent(userData![key])).join('&')
                                : '';
            const finalUrl = url + '?scheme=' + scheme + ((queryString !== '') ? '&' + queryString : '');
            window.open(finalUrl, this.popupDescriptor.popupTitle, this.popupDescriptor.features);
        }
    }

    //#endregion

    //#region onChange

    private onChange(): void {
        this._subscribers.forEach(func => func(this));
    }

    public addOnChange(func: (eventSource: AuthService<T>) => void): void {
        if (func !== undefined && func !== null) { this._subscribers.add(func); }
    }

    public removeOnChange(func: (eventSource: AuthService<T>) => void): boolean {
        return this._subscribers.delete(func);
    }

    //#endregion
}
