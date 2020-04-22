import { IAuthenticationInfo, IUserInfo, IUserSchemeInfo } from '../authService.model.public';

/** Defines the immutable contract of an authentication info implementation. */
export interface IAuthenticationInfoImpl<T extends IUserInfo> extends IAuthenticationInfo<T> {
   
     /**
     * Checks current expiration dates and returns this StdAuthenticationInfo or an updated one if changed.
     * @param utcNow The date to consider to challenge current expires and criticalExpires properties.
     */
    checkExpiration(utcNow?: Date): IAuthenticationInfoImpl<T>;

     /**
     * Sets the expires date and checks its expiration based on utcNow parameter.
     * Returns this StdAuthenticationInfo or an updated one if changed.
     * Note that, by design, expires is necessarily before or equal to criticalExpires and this
     * method ensures this invariant.
     * @param expires The new expires value. Undefined to clear it (level is no more Normal nor Critical).
     * @param utcNow The date to consider to challenge expirations.
     */
    setExpires(expires?: Date, utcNow?: Date): IAuthenticationInfoImpl<T>;

    /**
     * Sets the criticalExpires date and checks its expiration based on utcNow parameter.
     * Returns this StdAuthenticationInfo or an updated one if changed.
     * Note that, by design, expires is necessarily before or equal to criticalExpires and this
     * method ensures this invariant.
     * @param criticalExpires The new critical expires value. Undefined to clear it (level is no more Critical).
     * @param utcNow The date to consider to challenge expirations.
     */
    setCriticalExpires(criticalExpires?: Date, utcNow?: Date): IAuthenticationInfoImpl<T>;

    /**
     * Returns a new StdAuthenticationInfo where the user may no more be the actualUser.
     * Note that the expiration dates are checked based on the utcNow parameter.
     * @param user Creates a new StdAuthenticationInfo where the user is changed.
     * @param utcNow The date to consider to challenge expirations.
     */
    impersonate(user: IUserInfo, utcNow?: Date): IAuthenticationInfoImpl<T>;

    /**
     * Returns a new StdAuthenticationInfo (or this one if isImpersonated is already false and
     * checkExpiration did not change anything) where the unsafeActualUser is the same as
     * the actualUser.
     * Note that the expiration dates are checked based on the utcNow parameter.
     * @param utcNow The date to consider to challenge expirations.
     */
    clearImpersonation(utcNow?: Date): IAuthenticationInfoImpl<T>;

    /**
     * Generates a JSON compatible object for this Authentication info.
     */
    toJSON() : Object 
}

/** Defines a type system that exposes a type manager for IUserInfo and for IAuthenticationInfo. */
export interface IAuthenticationInfoTypeSystem<T extends IUserInfo> {   
    readonly userInfo: IUserInfoType<T>;
    readonly authenticationInfo: IAuthenticationInfoType<T>;
}

/** Type driver for IAuthenticationInfo.  */
export interface IAuthenticationInfoType<T extends IUserInfo> {

    /** Gets the None authentication (empty pattern), bound to Anonymous users. */
    readonly none: IAuthenticationInfoImpl<T>;

    /**
     * Factory method.
     * @param user The user information.
     * @param expires The optional expiration date.
     * @param criticalExpires The optional critical expiration date.
     */
    create(user: T, expires?: Date, criticalExpires?: Date): IAuthenticationInfoImpl<T>;

    /**
     * Maps an object (by parsing it) into a necessarily valid authentication info or null if
     * the given object o is false-ish.
     * @param o Any object that must be shaped like an authentication info.
     * @param availableSchemes The optional list of available schemes. When empty, all user schemes' status is Active.
     */
    fromJson( o: Object, availableSchemes?: ReadonlyArray<string> ): IAuthenticationInfoImpl<T>|null;

    /**
     * Generates a JSON compatible object for the Authentication info.
     * @param auth The authentication information to serialize.
     */
    toJSON( auth: IAuthenticationInfoImpl<IUserInfo> ) : Object;
    
    /**
     * Saves the authentication info and currently available schemes into the local storage.
     * @param storage Storage API to use.
     * @param endPoint The authentication end point. Informations are stored relatively to this end point. 
     * @param auth The authentication info to save. Null to remove current authentication information.
     * @param schemes Optional available schemes to save. By default, any existing persisted schemes are left as-is.
     */
    saveToLocalStorage( storage: Storage, endPoint: string, auth: IAuthenticationInfoImpl<T>|null, schemes?: ReadonlyArray<string> ): void

    /**
     * Returns the authentication and available schemes previously saved by saveToLocalStorage.
     * @param storage Storage API to use.
     * @param endPoint The authentication end point. Informations are stored relatively to this end point. 
     * @param availableSchemes
     * The optional list of available schemes that are used to update the users' scheme's state (Unused/Active/Deprecated).
     * When specified (not null nor undefined), this parameter takes precedence over the schemes persisted in the local storage (if any).
     */
    loadFromLocalStorage( storage: Storage, endPoint: string, availableSchemes? : ReadonlyArray<string> ) : [IAuthenticationInfoImpl<T>|null,ReadonlyArray<string>]
}

export interface IUserInfoType<T extends IUserInfo> {
    readonly anonymous: T;

    create(userId: number, userName: string, schemes: IUserSchemeInfo[]): T;

    /**
     * Maps an object (by parsing it) into a necessarily valid user information or null if
     * the given object o is false-ish.
     * @param o Any object that must be shaped like a T.
     * @param availableSchemes The optional list of available schemes. When empty, all user schemes' status is Active.
     */
    fromJson(o: object, availableSchemes?: ReadonlyArray<string> ): T|null;
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
