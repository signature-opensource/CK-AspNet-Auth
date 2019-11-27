export enum AuthLevel {
    None = 0,
    Unsafe,
    Normal,
    Critical
}

export enum SchemeUsageStatus {
    Used,
    Unused,
    Deprecated
}

export interface IAuthenticationInfo<T extends IUserInfo = IUserInfo> {
    readonly user: T;
    readonly unsafeUser: T;
    readonly actualUser: T;
    readonly unsafeActualUser: T;
    readonly expires: Date;
    readonly criticalExpires: Date;
    readonly isImpersonated: boolean;
    readonly level: AuthLevel;
}

export interface IUserInfo {
    readonly userId: number;
    readonly userName: string;
    readonly schemes: ReadonlyArray<IUserSchemeInfo>;
}

export interface IUserSchemeInfo {
    readonly name: string;
    readonly lastUsed: Date;
    readonly status: SchemeUsageStatus;
}

export interface IWebFrontAuthError {
    readonly type: string;
    readonly errorId: string;
    readonly errorReason: string;
    readonly error: IResponseError | ILoginError
}

export interface IResponseError {
    readonly errorId: string;
    readonly errorReason: string;
}

export interface ILoginError {
    readonly loginFailureCode: number;
    readonly loginFailureReason: string;
}

export interface IAuthServiceConfiguration {
    readonly identityEndPoint: IEndPoint;
    readonly localStoragePersistence?: ILocalStoragePersistence;
}

export interface IEndPoint {
    readonly hostname?: string;
    readonly port?: number;
    readonly disableSsl?: boolean;
}

export interface ILocalStoragePersistence {
    readonly onBasicLogin: boolean;
    readonly onRefresh: boolean;
    readonly onUnsafeDirectLogin: boolean;
    readonly onStartLogin: boolean;
}
