import { IAuthenticationInfo, IUserInfo, IUserSchemeInfo } from '../authService.model.public';

export interface IAuthenticationInfoTypeSystem<T extends IUserInfo> {
    readonly userInfo: IUserInfoType<T>;
    readonly authenticationInfo: IAuthenticationInfoType<T>;
}

export interface IAuthenticationInfoType<T extends IUserInfo> {
    readonly none: IAuthenticationInfo<T>;
    
    create( user: T, expires?: Date, criticalExpires?: Date ): IAuthenticationInfo<T>;

    fromJson( o: object ): IAuthenticationInfo<T>;
}

export interface IUserInfoType<T extends IUserInfo> {
    readonly anonymous: T;

    create( userId: number, userName: string, schemes: IUserSchemeInfo[] ): T;

    fromJson( o: object ): T;
}
