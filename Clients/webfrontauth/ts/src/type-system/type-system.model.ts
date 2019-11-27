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

    /**
     * Maps an object (by parsing it) into a necessarily valid authentication info.
     * @param o Any object that must be shaped like an authentication info.
     * @param availableSchemes The optional list of available schemes. When empty, all user schemes' status is Active.
     */
    fromJson(o: object, availableSchemes?: ReadonlyArray<string> ): IAuthenticationInfoImpl<T>;

    /**
     * Saves the authentication info and currently available schemes into the local storage.
     * @param storage Storage API to use.
     * @param endPoint The authentication end point.  
     * @param auth The authentication info to save.
     * @param schemes The available schemes to save.
     */
    saveToLocalStorage( storage: Storage, webFrontAuthEndPoint: string, auth: IAuthenticationInfoImpl<T>, schemes: ReadonlyArray<string> ) 

    /**
     * Returns the authentication and available schemes previously saved by saveToLocalStorage.
     * @param storage Storage API to use.
     * @param endPoint The authentication end point.  
     * @param availableSchemes Current available schemes: when not empty, the saved schemes are ignored.
     */
    loadFromLocalStorage( storage: Storage, webFrontAuthEndPoint: string, availableSchemes : ReadonlyArray<string> ) : [IAuthenticationInfoImpl<T>,ReadonlyArray<string>]
}

export interface IUserInfoType<T extends IUserInfo> {
    readonly anonymous: T;

    create(userId: number, userName: string, schemes: IUserSchemeInfo[]): T;

    /**
     * Maps an object (by parsing it) into a necessarily valid user information.
     * @param o Any object that must be shaped like a T.
     * @param availableSchemes The optional list of available schemes. When empty, all user schemes' status is Active.
     */
    fromJson(o: object, availableSchemes?: ReadonlyArray<string> ): T;
}

export class StdKeyType {
  public static readonly userName: string = 'name';
  public static readonly userId: string = 'id';
  public static readonly schemes: string = 'schemes';
  public static readonly expiration: string = 'exp';
  public static readonly criticalExpiration: string = 'cexp';
  public static readonly user: string = 'user';
  public static readonly actualUser: string = 'actualUser';
}
