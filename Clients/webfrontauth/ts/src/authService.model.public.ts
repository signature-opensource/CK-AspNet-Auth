
/** Defines the 4 possible levels of authentication. */
export enum AuthLevel {
    /** None authentication level is for the Anonymous user. */
    None = 0,
    /** Unsafe authentication level: @see IAuthenticationInfo.user is necessarily Anonymous.*/
    Unsafe,
    /** Normal authentication level.*/
    Normal,
    /** Critical authentication level must be active for a short time.*/
    Critical
}

/** Defines the status of the user schemes (see @see IUserSchemeInfo). */
export enum SchemeUsageStatus {
    /** The scheme has been used and is available. */
    Active,
    /** The scheme has not been used by the user and is available. */
    Unused,
    /** 
     * The scheme has been used by the user but is currently not available: user should
     * be invited to login through another scheme. 
     * */
    Deprecated
}

/**
 * Primary interface that captures the authentication info with its level and potential impersonations.
 * This must be implemented as an immutable object.
 */
export interface IAuthenticationInfo<T extends IUserInfo = IUserInfo> {
    
    /** 
     * Gets the user information as long as the level is AuthLevel.Normal or AuthLevel.Critical. 
     * When AuthLevel.None or AuthLevel.Unsafe, this is the Anonymous user information. 
     * */
    readonly user: T;
    
    /** Gets the user information, regardless of the level. */
    readonly unsafeUser: T;
    
    /** 
     * Gets the actual user information as long as the level is AuthLevel.Normal or AuthLevel.Critical. 
     * When AuthLevel.None or AuthLevel.Unsafe, this is the Anonymous user information. 
     * This actual user is not the same as this user if isImpersonated is true.
    */
    readonly actualUser: T;
    
    /** 
     * Gets the unsafe actual user information regardless of the level.  
     * This actual user is not the same as this user if isImpersonated is true.
    */
    readonly unsafeActualUser: T;
    
    /** 
     * Gets the expiration date. This is undefined if this information has already expired. 
     * This expires is guaranteed to be after (or equal to) criticalExpires.
    */
    readonly expires?: Date;
    
    /** 
     * Gets the critical expiration date. 
     * This is undefined if this information has no critical expiration date, ie. when level is not AuthLevel.Critical. 
     * When defined, this criticalExpires is guaranteed to be before (or equal to) expires.
     */
    readonly criticalExpires?: Date;
    
    /** 
     * Gets whether an impersonation is active here: unsafeUser is not the same as the unsafeActualUser.
     * Note that user and actualUser may be both the Anonymous user if level is AuthLevel.None 
     * or AuthLevel.Unsafe.
     */
    readonly isImpersonated: boolean;

    /** Gets the authentication level. */
    readonly level: AuthLevel;
}

/** Captures user informations. */
export interface IUserInfo {
    
    /** Gets the user identifier. 0 for the Anonymous user. */
    readonly userId: number;
    
    /** Gets the user name. This is the empty string for the Anonymous user. */
    readonly userName: string;

    /** 
     * Gets the authentication schemes that this user has used to authenticate so far.
     * This is empty for Anonymous user.  
     */
    readonly schemes: ReadonlyArray<IUserSchemeInfo>;
}

/** Describes the authentication schemes available or used by a user. */
export interface IUserSchemeInfo {
    /** Gets the scheme name. */
    readonly name: string;
    /** Gets the last used date. */
    readonly lastUsed: Date;
    /** Gets this scheme's status. */
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
    /** 
     * Gets the configuration of the local storage persistence.
     * When not defined, local storage is enabled (if available) for the 4 actions.
     * @see ILocalStoragePersistence.
     */
    readonly localStoragePersistence?: ILocalStoragePersistence;
}

export interface IEndPoint {
    readonly hostname?: string;
    readonly port?: number;
    readonly disableSsl?: boolean;
}

/** 
 * Defines whether unsafe authentication info should be stored into the local storage (if available)
 * and used as a fallback whenever the specified action failed to reach the server.
 */
export interface ILocalStoragePersistence {
    /** True to allow basic login to reuse the saved unsafe authentication info whenever the server is not reachable. */
    readonly onBasicLogin: boolean;
    /** True to allow refresh to reuse the saved unsafe authentication info whenever the server is not reachable. */
    readonly onRefresh: boolean;
    /** True to allow an unsafe direct login to reuse the saved unsafe authentication info whenever the server is not reachable. */
    readonly onUnsafeDirectLogin: boolean;
    /** True to allow a start login to reuse the saved unsafe authentication info whenever the server is not reachable. */
    readonly onStartLogin: boolean;
    /** Gets the boolean configuration by its name. */
    [index: string] : boolean | undefined;
}
