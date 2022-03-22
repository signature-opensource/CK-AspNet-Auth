import { AxiosRequestConfig, AxiosError, AxiosInstance } from 'axios';

import { IWebFrontAuthResponse, AuthServiceConfiguration } from './index.private';
import { AuthLevel, IAuthenticationInfo, IUserInfo, IAuthServiceConfiguration, IWebFrontAuthError } from './authService.model.public';
import { WebFrontAuthError } from './authService.model.extension';
import { IAuthenticationInfoTypeSystem, IAuthenticationInfoImpl } from './type-system/type-system.model';
import { StdAuthenticationTypeSystem } from './type-system';
import { PopupDescriptor } from './PopupDescriptor';
import { version } from './AuthService.version';

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
    private _interceptor: number;
    private _typeSystem: IAuthenticationInfoTypeSystem<T>;
    private _popupDescriptor: PopupDescriptor | undefined;
    private _expTimer : ReturnType<typeof setTimeout> | undefined;
    private _cexpTimer : ReturnType<typeof setTimeout> | undefined;

    private _subscribers: Set<(eventSource: AuthService) => void>;
    private _onMessage?: (this: Window, ev: MessageEvent) => void;
    private _closed: boolean;
    private _checkVersion: boolean;

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
    /** Gets the Authentication server version. This must be the same as this clientVersion otherwise behavior is not guaranteed. */
    public get endPointVersion(): string { return this._endPointVersion; }
    /** Gets this client version. This must be the same as the endPointVersion otherwise behavior is not guaranteed. */
    public static get clientVersion(): string { return version; }
    /** Gets the current error if any. */
    public get currentError(): IWebFrontAuthError|undefined { return this._currentError; }
    /** Gets the TypeSystem that manages AuthenticationInfo and UserInfo.*/
    public get typeSystem(): IAuthenticationInfoTypeSystem<T> { return this._typeSystem; }
    /** Gets whether this AuthService is closed: no method should be called anymore. */
    public get isClosed(): boolean { return this._closed; }

    public get popupDescriptor(): PopupDescriptor {
        if (!this._popupDescriptor) { this._popupDescriptor = new PopupDescriptor(); }
        return this._popupDescriptor;
    }
    public set popupDescriptor(popupDescriptor: PopupDescriptor) {
        if (popupDescriptor) { this._popupDescriptor = popupDescriptor; }
    };

    //#region constructor

    /**
     * Instantiates a new AuthService. Note that the 'refresh' method must be called.
     * It is simpler and safer to use the factory method 'createAsync' that fully initializes
     * the AuthService before returning it.
     * @param configuration The required configuration (endpoint and whether local storage should be used).
     * @param axiosInstance The axios instance that will be used. An interceptor is automatically registered that adds the token to each request (under control of {@link shouldSetToken}).
     * @param typeSystem Optional specialized type system that manages AuthenticationInfo and UserInfo.
     */
    constructor(
        configuration: IAuthServiceConfiguration,
        axiosInstance: AxiosInstance,
        typeSystem?: IAuthenticationInfoTypeSystem<T>
        ) {
        if (!configuration) { throw new Error('Configuration must be defined.'); }
        this._configuration = new AuthServiceConfiguration(configuration);

        if (!axiosInstance) { throw new Error('AxiosInstance must be defined.'); }
        this._axiosInstance = axiosInstance;
        this._interceptor = this._axiosInstance.interceptors.request.use(this.onIntercept());

        this._closed = false;
        this._checkVersion = !configuration.skipVersionsCheck;
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
            this._onMessage = this.onMessage();
            window.addEventListener('message', this._onMessage, false);
        }

        this.localDisconnect();
    }

    /**
     * Factory method that instantiates a new AuthService and calls the asynchronous refresh before
     * returning the service.
     * @param configuration The required configuration (endpoint and whether local storage should be used).
     * @param axiosInstance The axios instance that will be used. An interceptor is automatically registered that adds the token to each request (under control of {@link shouldSetToken}).
     * @param typeSystem Optional specialized type system that manages AuthenticationInfo and UserInfo.
     * @param throwOnError True to throw if any error occurred (server cannot be reached, protocol error, etc.)
     * @returns A new AuthService that may have a currentError if parameter throwOnError is false (the default).
     */
    public static async createAsync<T extends IUserInfo = IUserInfo>(
        configuration: IAuthServiceConfiguration,
        axiosInstance: AxiosInstance,
        typeSystem?: IAuthenticationInfoTypeSystem<T>,
        throwOnError: boolean = false
    ): Promise<AuthService> {
        const authService = new AuthService<T>(configuration, axiosInstance, typeSystem);
        await authService.refresh(true);
        if (authService.currentError) {
            console.error(
                'Error while initalizing new AuthService.',
                authService.currentError.errorId,
                authService.currentError.errorText
            );

            if (throwOnError) {
                authService.close();
                throw new Error('Unable to initalize a new AuthService. See logs.');
            }
        }
        return authService;
    }

    /**
     * Closes this AuthService, ejecting the axios interceptor, the window message hook
     * and clearing onChange subscriptions.
     * This can be called multiple times.
     */
    public close(): void
    {
        if(!this._closed){
            this._closed = true;
            this.clearTimeouts();
            this._subscribers.clear();
            this._axiosInstance.interceptors.request.eject(this._interceptor);
            if( this._onMessage ) window.removeEventListener('message', this._onMessage, false);
        }
    }

    private checkClosed() { if(this._closed) throw new Error("This AuthService has been closed."); }

    //#endregion

    //#region events

    private readonly maxTimeout: number = 2147483647;

    private static getSafeTimeDifference(timeDifference: number): number {
        return timeDifference * 2/3;
    }

    private setExpirationTimeout(): void {
        const timeDifference = this._authenticationInfo.expires!.getTime() - Date.now();

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
            }, AuthService.getSafeTimeDifference(timeDifference));
        }
    }

    private setCriticialExpirationTimeout(): void {
        const timeDifference = this._authenticationInfo.criticalExpires!.getTime() - Date.now();

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
            }, AuthService.getSafeTimeDifference(timeDifference));
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
                this.handleServerResponse(messageEvent.data.data);
            }
        };
    }

    //#endregion

    //#region request handling

    /**
     * When the server cannot be reached, there is no point to call localDisconnect(): we'd better wait its availability.
     * Actually, when we are refreshing and the current authentication is None and the LocalStorage
     * is enabled, we restore the available schemes and the Authentication info from the local storage.
     *
     * When the server returns an HTTP error, whether we should lose the local authentication
     * (i.e call localDisconnect) is questionable...
     * 4XX (Client errors) means that someting's wrong in the payload we sent (an invalid user data for instance): such a client
     * error should not lose the current authentication.
     * Same for 5XX (server errors), it may be a bad handling of a Client error, or the server is temporary unavailable.
     * However, a 1XX (information), a 3XX (redirection) are NOT in the protocol (and browsers silently follow them anyway).
     * This is weird. Just like if we receive an out-of-band status (600).
     * But how does this impact our current local authentication information?
     * Disconnecting the user here doesn't seem to provide any benefits...
     *
     * The only thing we can do on error is checking the current authentication expiration to update it
     * regardless of the timeouts (since they have been disabled) and reenable them.
     *
     * When the server returned a 200, then the repsonse is applied, no matter what: it may result in a
     * localDisconnect and this is fine.
     *
     * Error handling is never easy...
     *
     * @param entryPoint
     * @param requestOptions
     * @param skipResponseHandling
     */
    private async sendRequest(
        entryPoint: 'basicLogin' | 'unsafeDirectLogin' | 'refresh' | 'impersonate' | 'logout' | 'startLogin',
        requestOptions: { body?: object, queries?: Array<string | { key: string, value: string }> },
        skipResponseHandling: boolean = false
    ): Promise<void> {
        try {
            this.clearTimeouts(); // We clear timeouts beforehand to avoid concurent requests

            const query = this.buildQueryString( requestOptions.queries );
            const response = await this._axiosInstance.post<IWebFrontAuthResponse>(
                `${this._configuration.webFrontAuthEndPoint}.webfront/c/${entryPoint}${query}`,
                !!requestOptions.body ? JSON.stringify(requestOptions.body) : {},
                { withCredentials: true });

            const status = response.status;
            if (status === 200 ) {
                if (!skipResponseHandling ) {
                    this.handleServerResponse(response.data);
                }
                // Done (handleServerResponse did its job or there is nothing to do).
                return;
            }
            // Sets the current error (weird success status).
            this._currentError = new WebFrontAuthError({
                errorId: `HTTP.Status.${status}`,
                errorText: 'Unhandled success status'
            });
        } catch (error) {

            // This should not happen too often nor contain dangerous secrets...
            console.log( 'Exception while sending '+entryPoint+' request.', error );

            const axiosError = error as AxiosError;
            if (!(axiosError && axiosError.response)) {
                // Connection issue (no axios response): 408 is Request Timeout.
                this._currentError = new WebFrontAuthError({
                    errorId: 'HTTP.Status.408',
                    errorText: 'No connection could be made'
                });
                // If we are refreshing and there is no connection to the server, and the current level is None,
                /// we challenge the local storage and try to restore the available schemes and (unsafe) authentication.
                if( this._authenticationInfo.level == AuthLevel.None
                    && entryPoint === 'refresh'
                    && this._configuration.localStorage ) {

                    const [auth,schemes] = this._typeSystem.authenticationInfo.loadFromLocalStorage( this._configuration.localStorage,
                                                                                                     this._configuration.webFrontAuthEndPoint,
                                                                                                     this._availableSchemes );
                    this._availableSchemes = schemes;
                    if( auth )
                    {
                        // This sets the (unsafe, no expiration) auth and trigger the onChange: we are done.
                        this.localDisconnect( auth );
                        return;
                    }
                }
            }
            else {
                // Sets the current error.
                const errorResponse = axiosError.response;
                const data = errorResponse.data as IWebFrontAuthResponse || {};

                this._currentError = new WebFrontAuthError({
                    errorId: data.errorId || `HTTP.Status.${errorResponse.status}`,
                    errorText: data.errorText || 'Server response error'
                });
            }
        }
        // There has been an error.
        const a = this._authenticationInfo.checkExpiration();
        if( a != this._authenticationInfo )
        {
            this._authenticationInfo = a;
            this.onNewAuthenticationInfo();
        }
        else
        {
            this.onChange();
        }
    }

    private handleServerResponse(r: IWebFrontAuthResponse): void {
        if (!r) {
            this.localDisconnect();
            return;
        }

        this._currentError = undefined;

        // Checking the version first.
        if (r.version) {
            // Only refresh returns the version.
            this._endPointVersion = r.version;
            if( this._checkVersion && this._endPointVersion != AuthService.clientVersion )
            {
                const msg = `Client/Server version mismatch! this client version is '${AuthService.clientVersion}' but endpoint's version is '${this._endPointVersion}'.`;
                this._currentError = new WebFrontAuthError({
                    errorId: 'ClientEndPointVersionMismatch',
                    errorText: msg
                });
                throw new Error(msg);
            }
        }
       if (r.schemes) { this._availableSchemes = r.schemes; }

        if (r.loginFailureCode && r.loginFailureReason) {
            this._currentError = new WebFrontAuthError({
                loginFailureCode: r.loginFailureCode,
                loginFailureReason: r.loginFailureReason
            });
        }

        if (r.errorId && r.errorText) {
            this._currentError = new WebFrontAuthError({
                errorId: r.errorId,
                errorText: r.errorText
            });
        }

        if (this._currentError) {
            this.localDisconnect();
            return;
        }


        if (!r.info) {
            this.localDisconnect();
            return;
        }

        this._token = r.token ? r.token : '';
        this._refreshable = r.refreshable ? r.refreshable : false;
        this._rememberMe = r.rememberMe ? r.rememberMe : false;

        const info = this._typeSystem.authenticationInfo.fromServerResponse(r.info, this._availableSchemes) ;
        this._authenticationInfo = info !== null ? info : this._typeSystem.authenticationInfo.none.setDeviceId(this._authenticationInfo.deviceId);

        this.onNewAuthenticationInfo();
    }

    private onNewAuthenticationInfo() {
        if (this._authenticationInfo.expires) {
            this.setExpirationTimeout();
            if (this._authenticationInfo.criticalExpires) { this.setCriticialExpirationTimeout(); }
        }
        if (this._configuration.localStorage) {
            this._typeSystem.authenticationInfo.saveToLocalStorage(
                this._configuration.localStorage,
                this._configuration.webFrontAuthEndPoint,
                this._authenticationInfo,
                this._availableSchemes);
        }
        this.onChange();
    }

    private localDisconnect( fromLocalStorage?: IAuthenticationInfoImpl<T> ): void {
        // Keep (and applies) the current rememberMe configuration: this is the "local" disconnect.
        this._token = '';
        this._refreshable = false;
        if( fromLocalStorage ) this._authenticationInfo = fromLocalStorage;
        else if( this._rememberMe ) {
            this._authenticationInfo = this._authenticationInfo.setExpires();
        }
        else {
            this._authenticationInfo = this._typeSystem.authenticationInfo.none.setDeviceId( this._authenticationInfo.deviceId );
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
     * @param impersonateActualUser True to impersonate the current actual user if any. Defaults to false.
     * @param userData Optional user data that the server may use.
     */
    public async basicLogin(userName: string, password: string, rememberMe?: boolean, impersonateActualUser?: boolean, userData?: object): Promise<void> {
        this.checkClosed();
        if( rememberMe === undefined ) rememberMe = this._rememberMe;
        await this.sendRequest('basicLogin', { body: { userName, password, userData, rememberMe, impersonateActualUser } });
    }

    /**
     * Triggers a direct, unsafe login (this has to be explicitly allowed by the server).
     * @param provider The authentication scheme to use.
     * @param rememberMe False to avoid any memorization (a session cookie is used). When undefined, the current rememberMe value is used.
     * @param payload The object payload that contain any information required to authenticate with the scheme.
     * @param impersonateActualUser True to impersonate the current actual user if any. Defaults to false.
     * @param userData Optional user data that the server may use.
     */
    public async unsafeDirectLogin(provider: string, payload: object, rememberMe?: boolean, impersonateActualUser?: boolean, userData?: object): Promise<void> {
        this.checkClosed();
        if( rememberMe === undefined ) rememberMe = this._rememberMe;
        await this.sendRequest('unsafeDirectLogin', { body: { provider, payload, userData, rememberMe, impersonateActualUser } });
    }

    /**
     * Refreshes the current authentication.
     * @param callBackend True to trigger a refresh of the authentication on the backend: the backend IWebFrontAuthLoginService.RefreshAuthenticationInfoAsync
     * is called so that user information (the user name) can be updated.
     *  When false (the default), the server trusts the current authentication and may renew its expiration (according to its configuration).
     * @param requestSchemes True to force a refresh of the availableSchemes (this is automatically
     * true when current availableSchemes is empty).
     * @param requestVersion True to force a refresh of the version (this is automatically
     * true when current endPointVersion is the empty string).
     */
    public async refresh(callBackend: boolean = false, requestSchemes: boolean = false, requestVersion: boolean = false): Promise<void> {
        this.checkClosed();
        const queries: string[] = [];
        if (callBackend) { queries.push('callBackend'); }
        if (requestSchemes || this._availableSchemes.length === 0 ) { queries.push('schemes'); }
        if (requestVersion || this._endPointVersion === '') { queries.push('version'); }
        await this.sendRequest('refresh', { queries });
    }

    /**
     * Request an impersonation to a user. This may be honored or not by the server.
     * @param user The user into whom the currently authenticated user wants to be impersonated.
     */
    public async impersonate(user: string | number): Promise<void> {
        this.checkClosed();
        const requestOptions = { body: (typeof user === 'string') ? { userName: user } : { userId: user } };
        await this.sendRequest('impersonate', requestOptions);
    }

    /**
     * Revokes the current authentication.
     * This removes any memory of the current authentication.
     */
    public async logout(): Promise<void> {
        this.checkClosed();
        this._token = '';
        await this.sendRequest('logout', {}, /* skipResponseHandling */ true);
        if( this._configuration.localStorage ) {
            this._typeSystem.authenticationInfo.saveToLocalStorage(
                this._configuration.localStorage,
                this._configuration.webFrontAuthEndPoint,
                null,
                [] )
        }
        await this.refresh();
    }

     /**
     * Starts an inline login with the provided scheme. Local context is lost since the process will go through one or more pages
     * before redirecting to the provided return url.
     * @param provider The authentication scheme to use.
     * @param returnUrl The final return url.
     * @param rememberMe False to avoid any memorization (a session cookie is used). When undefined, the current rememberMe value is used.
     * @param impersonateActualUser True to impersonate the current actual user if any. Defaults to false.
     * @param userData Optional user data that the server may use.
     */
      public async startInlineLogin(scheme: string, returnUrl: string, rememberMe?: boolean, impersonateActualUser?: boolean, userData?: object): Promise<void> {
        this.checkClosed();
        if (!returnUrl) { throw new Error('returnUrl must be defined.'); }
        if (!(returnUrl.startsWith('http://') || returnUrl.startsWith('https://'))) {
            if (returnUrl.charAt(0) !== '/') { returnUrl = '/' + returnUrl; }
            returnUrl = document.location.origin + returnUrl;
        }

        const params = [
            { key: 'returnUrl', value: encodeURIComponent(returnUrl) },
            rememberMe ? 'rememberMe' : '',
            impersonateActualUser ? 'impersonateActualUser' : ''
        ];
        document.location.href = this.buildStartLoginUrl( scheme, params, userData );
    }

     /**
     * Starts a login process in a popup window: this is the preferred way to do.
     * @param provider The authentication scheme to use.
     * @param rememberMe False to avoid any memorization (a session cookie is used). When undefined, the current rememberMe value is used.
     * @param impersonateActualUser True to impersonate the current actual user if any. Defaults to false.
     * @param userData Optional user data that the server may use.
     */
    public async startPopupLogin(scheme: string, rememberMe?: boolean, impersonateActualUser?: boolean, userData?: {[index:string]: any}): Promise<void> {
        this.checkClosed();
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
                    await this.basicLogin(loginData.username, loginData.password, loginData.rememberMe, false, userData);

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
            const data = [
                { key: 'callerOrigin', value: encodeURIComponent(document.location.origin) },
                rememberMe ? 'rememberMe' : '',
                impersonateActualUser ? 'impersonateActualUser' : ''
            ];
            window.open(this.buildStartLoginUrl(scheme, data, userData), this.popupDescriptor.popupTitle, this.popupDescriptor.features);
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
        this.checkClosed();
        if(!url) throw new Error("Url should not be null or undefined")
        if(this._token === "") return false;
        return url.startsWith(this._configuration.webFrontAuthEndPoint);
    }

    //#endregion

    //#region onChange

    private onChange(): void {
        this._subscribers.forEach(func => func(this));
    }

    /**
     * Registers a callback function that will be called on any change.
     * @param func A callback function that will be called whenever something changes.
     */
    public addOnChange(func: (eventSource: AuthService) => void): void {
        this.checkClosed();
        if (func !== undefined && func !== null) { this._subscribers.add(func); }
    }

    /**
     * Unregister a previously registered callback.
     * @param func The callback function to remove.
     * @returns True if the callback has been found and removed, false otherwise.
     */
    public removeOnChange(func: (eventSource: AuthService) => void): boolean {
        this.checkClosed();
        return this._subscribers.delete(func);
    }
    //#endregion

    private buildQueryString( params?: Array<string | { key: string, value: string }>, scheme?: string ): string {
        let query = params && params.length
                ? `?${params.map(q => typeof q === 'string' ? q : `${q.key}=${q.value}`).join('&')}`
                : '';

        let schemeParam = scheme ? `scheme=${scheme}` : '';
        if( query && schemeParam )
        {
            query += `&${schemeParam}`;
        }
        else if( schemeParam )
        {
            query += `?${schemeParam}`;
        }

        return query;
    }

    private buildStartLoginUrl(
        scheme: string,
        params: Array<string | { key: string, value: string }>,
        userData?: { [index: string]: any }
    ): string {
        if( userData ) {
            Object.keys(userData).forEach( i => params.push({key: i, value: userData[i]}));
        }
        return `${this._configuration.webFrontAuthEndPoint}.webfront/c/startLogin${this.buildQueryString(params, scheme)}`;
    }

}
