export enum AuthLevel {
    None = 0,
    Unsafe,
    Normal,
    Critical
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
    readonly schemes: IUserSchemeInfo[];
}

export interface IUserSchemeInfo {
    readonly name: string;
    readonly lastUsed: Date;
}

export interface IWebFrontAuthError {
    readonly type: string;
    readonly errorId: string;
    readonly errorReason: string;
    readonly error: WellKnownError
}

export type WellKnownError = IResponseError | ILoginError;

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
}

export interface IEndPoint {
    readonly hostname?: string;
    readonly port?: number;
    readonly disableSsl?: boolean;
}
