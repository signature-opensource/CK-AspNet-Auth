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

export interface IError {
    readonly loginFailureCode: number;
    readonly loginFailureReason: string;
    readonly errorId: string;
    readonly errorReason: string;
}

export interface IAuthServiceConfiguration {
    readonly identityEndPoint: IEndPoint;
}

export interface IEndPoint {
    readonly hostname?: string;
    readonly port?: number;
    readonly disableSsl?: boolean;
}
