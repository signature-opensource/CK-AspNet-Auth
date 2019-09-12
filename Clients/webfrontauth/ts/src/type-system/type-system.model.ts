import { IAuthenticationInfo, IUserInfo, IUserSchemeInfo } from '../authService.model.public';

export interface IAuthenticationInfoImpl<T extends IUserInfo> extends IAuthenticationInfo<T> {
    checkExpiration(utcNow?: Date): IAuthenticationInfoImpl<T>;

    setExpires(expires: Date, utcNow?: Date): IAuthenticationInfoImpl<T>;

    setCriticalExpires(criticalExpires: Date, utcNow?: Date): IAuthenticationInfoImpl<T>;

    impersonate(user: IUserInfo, utcNow?: Date): IAuthenticationInfoImpl<T>;

    clearImpersonation(utcNow?: Date): IAuthenticationInfoImpl<T>;
}

export interface IAuthenticationInfoTypeSystem<T extends IUserInfo> {
    readonly userInfo: IUserInfoType<T>;
    readonly authenticationInfo: IAuthenticationInfoType<T>;
}

export interface IAuthenticationInfoType<T extends IUserInfo> {
    readonly none: IAuthenticationInfoImpl<T>;

    create(user: T, expires?: Date, criticalExpires?: Date): IAuthenticationInfoImpl<T>;

    fromJson(o: object): IAuthenticationInfoImpl<T>;
}

export interface IUserInfoType<T extends IUserInfo> {
    readonly anonymous: T;

    create(userId: number, userName: string, schemes: IUserSchemeInfo[]): T;

    fromJson(o: object): T;
}
