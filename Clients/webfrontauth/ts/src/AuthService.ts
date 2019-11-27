import { AxiosRequestConfig, AxiosError, AxiosInstance } from 'axios';

import { IAuthenticationInfo, IUserInfo, IAuthServiceConfiguration, IWebFrontAuthError } from './index';
import { IAuthenticationInfoTypeSystem, StdAuthenticationTypeSystem, PopupDescriptor, IAuthenticationInfoImpl, WebFrontAuthError } from './index.extension';
import { IWebFrontAuthResponse, AuthServiceConfiguration } from './index.private';

export class AuthService<T extends IUserInfo = IUserInfo> {

    private _authenticationInfo: IAuthenticationInfoImpl<T>;
    private _token: string;
    private _refreshable: boolean;
    private _availableSchemes: ReadonlyArray<string>;
    private _currentError: IWebFrontAuthError;
    private _version: string;
    private _configuration: AuthServiceConfiguration;

    private _axiosInstance: AxiosInstance;
    private _typeSystem: IAuthenticationInfoTypeSystem<T>;
    private _popupDescriptor: PopupDescriptor;

    private _expTimer;
    private _cexpTimer;

    private _subscribers: Set<(eventSource: AuthService) => void>;

    public get authenticationInfo(): IAuthenticationInfo<T> { return this._authenticationInfo; }
    public get token(): string { return this._token; }
    public get refreshable(): boolean { return this._refreshable; }
    public get availableSchemes(): ReadonlyArray<string> { return this._availableSchemes; }
    public get version(): string { return this._version; }
    public get currentError(): IWebFrontAuthError { return this._currentError; }

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
            if (authService.currentError.errorId) {
                console.error(
                    'Encoutered error while refreshing.',
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
        const timeDifference = this._authenticationInfo.expires.getTime() - Date.now()

        if (timeDifference > this.maxTimeout) {
            this._expTimer = setTimeout(this.setExpirationTimeout, this.maxTimeout);
        } else {
            this._expTimer = setTimeout(() => {
                if (this._refreshable) {
                    this.refresh();
                } else {
                    this._authenticationInfo = this._authenticationInfo.setExpires(null);
                    this.onChange();
                }
            }, timeDifference);
        }
    }

    private setCriticialExpirationTimeout(): void {
        const timeDifference = this._authenticationInfo.criticalExpires.getTime() - Date.now()

        if (timeDifference > this.maxTimeout) {
            this._cexpTimer = setTimeout(this.setCriticialExpirationTimeout, this.maxTimeout);
        } else {
            this._cexpTimer = setTimeout(() => {
                if (this._refreshable) {
                    this.refresh();
                } else {
                    this._authenticationInfo = this._authenticationInfo.setCriticalExpires(null);
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
            if (config.url.startsWith(this._configuration.webFrontAuthEndPoint) && this._token) {
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
        requestOptions?: { body?: object, queries?: Array<string | { key: string, value: string }> },
        skipResponseParsing: boolean = false
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
                if (!skipResponseParsing ) { this.parseResponse(response.data); }
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
                    if( storage !== null ) {
                        const [auth,schemes] = this._typeSystem.authenticationInfo.loadFromLocalStorage( storage, 
                                                                                        this._configuration.webFrontAuthEndPoint, 
                                                                                        this._availableSchemes );
                        if( auth )
                        {
                            this._availableSchemes = schemes;
                            this._currentError = null;
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

    private parseResponse(response: IWebFrontAuthResponse): void {
        if (!(response)) {
            this.localDisconnect();
            return;
        }

        const loginFailureCode: number = response.loginFailureCode;
        const loginFailureReason: string = response.loginFailureReason;
        const errorId: string = response.errorId;
        const errorReason: string = response.errorText;

        this._currentError = WebFrontAuthError.NoError;

        if (loginFailureCode && loginFailureReason) {
            this._currentError = new WebFrontAuthError({
                loginFailureCode: loginFailureCode,
                loginFailureReason: loginFailureReason
            });
        }

        if (errorId && errorReason) {
            this._currentError = new WebFrontAuthError({
                errorId,
                errorReason
            });
        }

        if (!!this._currentError.error) {
            this.localDisconnect();
            return;
        }

        if (response.version) { this._version = response.version; }
        if (response.schemes) { this._availableSchemes = response.schemes; }

        if (!response.info) {
            this.localDisconnect();
            return;
        }

        this._token = response.token ? response.token : '';
        this._refreshable = response.refreshable ? response.refreshable : false;
        this._authenticationInfo = this._typeSystem.authenticationInfo.fromJson(response.info, this._availableSchemes);

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

    public async basicLogin(userName: string, password: string, userData?: object): Promise<void> {
        await this.sendRequest('basicLogin', { body: { userName, password, userData } });
    }

    public async unsafeDirectLogin(provider: string, payload: object): Promise<void> {
        await this.sendRequest('unsafeDirectLogin', { body: { provider, payload } });
    }

    public async refresh(full: boolean = false, requestSchemes: boolean = false, requestVersion: boolean = false): Promise<void> {
        const queries = [];
        if (full) { queries.push('full'); }
        if (requestSchemes) { queries.push('schemes'); }
        if (requestVersion) { queries.push('version'); }
        await this.sendRequest('refresh', { queries });
    }

    public async impersonate(user: string | number): Promise<void> {
        const requestOptions = { body: (typeof user === 'string') ? { userName: user } : { userId: user } };
        await this.sendRequest('impersonate', requestOptions);
    }

    public async logout(full: boolean = false): Promise<void> {
        this._token = '';
        await this.sendRequest('logout', { queries: full ? ['full'] : [] }, /* skipResponseParsing */ true);
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
            popup.document.write(this.popupDescriptor.generateBasicHtml());

            const onClick = async () => {

                const usernameInput = popup.document.getElementById('username-input') as HTMLInputElement;
                const passwordInput = popup.document.getElementById('password-input') as HTMLInputElement;
                const errorDiv = popup.document.getElementById('error-div') as HTMLInputElement;
                const loginData = { username: usernameInput.value, password: passwordInput.value };

                if (!(loginData.username && loginData.password)) {
                    errorDiv.innerHTML = this.popupDescriptor.basicMissingCredentialsError;
                    errorDiv.style.display = 'block';
                } else {
                    await this.basicLogin(loginData.username, loginData.password, userData);

                    if (this.authenticationInfo.level >= 2) {
                        popup.close();
                    } else {
                        errorDiv.innerHTML = this.popupDescriptor.basicInvalidCredentialsError;
                        errorDiv.style.display = 'block';
                    }
                }
            }

            popup.document.getElementById('submit-button').onclick = (async () => await onClick());
        } 
        else {
            const url = `${this._configuration.webFrontAuthEndPoint}.webfront/c/startLogin`;
            userData = { ...userData, callerOrigin: document.location.origin };
            const queryString = Object.keys(userData).map((key) => encodeURIComponent(key) + '=' + encodeURIComponent(userData[key])).join('&');
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
