import { AxiosRequestConfig, AxiosError, AxiosInstance } from 'axios';

import { IWebFrontAuthResponse, AuthServiceConfiguration } from './index.private';
import { AuthLevel, IAuthenticationInfo, IUserInfo, IAuthServiceConfiguration, IWebFrontAuthError } from './authService.model.public';
import { WebFrontAuthError } from './authService.model.extension';
import { IAuthenticationInfoTypeSystem, IAuthenticationInfoImpl } from './type-system/type-system.model';
import { StdAuthenticationTypeSystem } from './type-system';
import { PopupDescriptor } from './PopupDescriptor';

export class AuthService<T extends IUserInfo = IUserInfo> {

    private _authenticationInfo: IAuthenticationInfoImpl<T>;
    private _token: string;
    private _rememberMe: boolean;
    private _refreshable: boolean;
    private _availableSchemes: ReadonlyArray<string>;
    private _endPointVersion: string;
    private _configuration: AuthServiceConfiguration;
    private _currentError?: IWebFrontAuthError;

    private _axiosInstance: AxiosInstance;
    private _typeSystem: IAuthenticationInfoTypeSystem<T>;
    private _popupDescriptor: PopupDescriptor | undefined;
    private _expTimer : number | undefined;
    private _cexpTimer : number | undefined;

    private _subscribers: Set<(eventSource: AuthService) => void>;

    /** Gets the current authentication information. */
    public get authenticationInfo(): IAuthenticationInfo<T> { return this._authenticationInfo; }
    /** Gets the current authentication token. This is the empty string when there is currently no authentication. */
    public get token(): string { return this._token; }
    /** Gets whether this service will automatically refreshes the authentication. */
    public get refreshable(): boolean { return this._refreshable; }
    /** Gets whether the current authentication should be memorized or considered a transient one. */
    public get rememberMe(): boolean { return this._rememberMe; }
    /** Gets the available authentication schemes names. */
    public get availableSchemes(): ReadonlyArray<string> { return this._availableSchemes; }
    /** Gets the Authentication server version. */
    public get endPointVersion(): string { return this._endPointVersion; }
    /** Gets the current error if any. */
    public get currentError(): IWebFrontAuthError|undefined { return this._currentError; }
    /** Gets the TypeSystem that manages AuthenticationInfo and UserInfo.*/
    public get typeSystem(): IAuthenticationInfoTypeSystem<T> { return this._typeSystem; }

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
        this._endPointVersion = '';
        this._availableSchemes = [];
        this._subscribers = new Set<() => void>();
        this._expTimer = undefined;
        this._cexpTimer = undefined;
        this._authenticationInfo = this._typeSystem.authenticationInfo.none;
        this._refreshable = false;
        this._rememberMe = false;
        this._token = '';
        this._popupDescriptor = undefined;

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
        if (this._expTimer ) {
            clearTimeout(this._expTimer);
            this._expTimer = undefined;
        }
        if (this._cexpTimer) {
            clearTimeout(this._cexpTimer);
            this._cexpTimer = undefined;
        }
    }

    private onIntercept(): (value: AxiosRequestConfig) => AxiosRequestConfig | Promise<AxiosRequestConfig> {
        return (config: AxiosRequestConfig) => {
            if( this._token
                && this.shouldSetToken(config.url!) ) {
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

            // This should not happen too often nor contain dangerous secrets...
            console.log( 'Exception while sending '+entryPoint+' request.', error );

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

        if (r.version) { this._endPointVersion = r.version; }
        if (r.schemes) { this._availableSchemes = r.schemes; }

        if (!r.info) {
            this.localDisconnect();
            return;
        }

        this._token = r.token ? r.token : '';
        this._refreshable = r.refreshable ? r.refreshable : false;
        this._rememberMe = r.rememberMe ? r.rememberMe : false;

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
        // Keep the current rememberMe configuration: this is the "local" disconnect.
        this._token = '';
        this._refreshable = false;
        if( authInfo ) this._authenticationInfo = authInfo;
        else if( this._rememberMe ) {
            this._authenticationInfo = this._authenticationInfo.setExpires();
        }
        else {
            const deviceId = this._authenticationInfo.deviceId;
            this._authenticationInfo = this._typeSystem.authenticationInfo.none.setDeviceId( deviceId );
        }
        this.clearTimeouts();
        this.onChange();
    }

    //#endregion

    //#region webfrontauth protocol

    /**
     * Triggers a basic login with a user name and password.
     * @param userName The user name.
     * @param password The password to use.
     * @param rememberMe False to avoid any memorization (a session cookie is used). When undefined, the current rememberMe value is used.
     * @param userData Optional user data that the server may use.
     */
    public async basicLogin(userName: string, password: string, rememberMe?: boolean, userData?: object): Promise<void> {
        if( rememberMe === undefined ) rememberMe = this._rememberMe;
        await this.sendRequest('basicLogin', { body: { userName, password, userData, rememberMe } });
    }

    /**
     * Triggers a direct, unsafe login (this has to be explicitly allowed by the server).
     * @param provider The authentication scheme to use.
     * @param rememberMe False to avoid any memorization (a session cookie is used). When undefined, the current rememberMe value is used.
     * @param payload The object payload that contain any information required to authenticate with the scheme.
     */
    public async unsafeDirectLogin(provider: string, payload: object, rememberMe?: boolean): Promise<void> {
        if( rememberMe === undefined ) rememberMe = this._rememberMe;
        await this.sendRequest('unsafeDirectLogin', { body: { provider, payload } });
    }

    /**
     * Refreshes the current authentication.
     * @param full True to force a full refresh of the authentication: the server will
     * challenge again the authentication against its backend.
     * @param requestSchemes True to force a refresh of the availableSchemes (this is automatically
     * true when current availableSchemes is empty).
     * @param requestVersion True to force a refresh of the version (this is automatically
     * true when current endPointVersion is the empty string).
     */
    public async refresh(full: boolean = false, requestSchemes: boolean = false, requestVersion: boolean = false): Promise<void> {
        const queries: string[] = [];
        if (full) { queries.push('full'); }
        if (requestSchemes || this._availableSchemes.length === 0 ) { queries.push('schemes'); }
        if (requestVersion || this._endPointVersion === '') { queries.push('version'); }
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

    public async startInlineLogin(scheme: string, returnUrl: string, rememberMe?: boolean, userData?: object): Promise<void> {
        if (!returnUrl) { throw new Error('returnUrl must be defined.'); }
        if (!(returnUrl.startsWith('http://') || returnUrl.startsWith('https://'))) {
            if (returnUrl.charAt(0) !== '/') { returnUrl = '/' + returnUrl; }
            returnUrl = document.location.origin + returnUrl;
        }

        const params = {
            returnUrl: encodeURI(returnUrl),
            callerOrigin : encodeURI(document.location.origin),
            rememberMe: rememberMe ? "1" : "0",
            userData: userData
        };
        const queryString = this.buildQueryString( params, scheme );
        document.location.href = this.buildStartLoginUrl( queryString );
    }

    public async startPopupLogin(scheme: string, rememberMe?: boolean, userData?: {[index:string]: any}): Promise<void> {
        if( rememberMe === undefined ) rememberMe = this._rememberMe;
        if (scheme === 'Basic') {
            const popup = window.open('about:blank', this.popupDescriptor.popupTitle, this.popupDescriptor.features);
            if( popup == null ) throw new Error( "Unable to open popup window." );

            popup.document.write(this.popupDescriptor.generateBasicHtml( rememberMe ));
            const onClick = async () => {

                const usernameInput = popup!.document.getElementById('username-input') as HTMLInputElement;
                const passwordInput = popup!.document.getElementById('password-input') as HTMLInputElement;
                const rememberMeInput = popup!.document.getElementById('remember-me-input') as HTMLInputElement;
                const errorDiv = popup!.document.getElementById('error-div') as HTMLInputElement;
                const loginData = { username: usernameInput.value, password: passwordInput.value, rememberMe: rememberMeInput.checked };

                if (!(loginData.username && loginData.password)) {
                    errorDiv.innerHTML = this.popupDescriptor.basicMissingCredentialsError;
                    errorDiv.style.display = 'block';
                } else {
                    await this.basicLogin(loginData.username, loginData.password, loginData.rememberMe, userData);

                    if (this.authenticationInfo.level >= AuthLevel.Normal) {
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
            userData = { ...userData, callerOrigin: document.location.origin, rememberMe: rememberMe };
            const queryString = this.buildQueryString( userData, scheme );
            window.open(this.buildStartLoginUrl(queryString), this.popupDescriptor.popupTitle, this.popupDescriptor.features);
        }
    }

    /**
     * Checks whether calling the provided url requires the header bearer token to be added or not.
     * Currently, only urls from the authentication endpoint should add the authentication token.
     * The url must exactly starts with the authentication backend address.
     * In the future, this may be extended to support other secure endpoints if needed.
     * @param url The url to be checked.
     */
    public shouldSetToken(url : string) : boolean {
        if(!url) throw new Error("Url should not be null or undefined")
        if(this._token === "") return false;
        return url.startsWith(this._configuration.webFrontAuthEndPoint);
    }

    //#endregion

    //#region onChange

    private onChange(): void {
        this._subscribers.forEach(func => func(this));
    }

    public addOnChange(func: (eventSource: AuthService) => void): void {
        if (func !== undefined && func !== null) { this._subscribers.add(func); }
    }

    public removeOnChange(func: (eventSource: AuthService) => void): boolean {
        return this._subscribers.delete(func);
    }

    public buildQueryString( params: { [index: string]: any }, scheme: string ) {
        return params ? `?scheme=${scheme}&${Object.keys( params ).map((key) => encodeURIComponent(key) + '=' + encodeURIComponent(params[key] as string)).join('&')}` : '';
    }

    public buildStartLoginUrl( query: string ) {
        return `${this._configuration.webFrontAuthEndPoint}.webfront/c/startLogin${query}`;
    }
    //#endregion
}
