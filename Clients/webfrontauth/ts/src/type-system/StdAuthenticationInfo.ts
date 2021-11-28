import { IUserInfo, AuthLevel } from '../authService.model.public';
import { IAuthenticationInfoTypeSystem, IAuthenticationInfoImpl } from './type-system.model';

/**
 * Standard immutable implementation for IAuthenticationInfo.
 */
export class StdAuthenticationInfo implements IAuthenticationInfoImpl<IUserInfo> {

    private readonly _typeSystem: IAuthenticationInfoTypeSystem<IUserInfo>;
    private readonly _user: IUserInfo;
    private readonly _actualUser: IUserInfo;
    private readonly _expires?: Date;
    private readonly _criticalExpires?: Date;
    private readonly _level: AuthLevel;
    private readonly _deviceId: string;

    /** 
     * Gets the user information as long as the @see level is @see AuthLevel.Normal or @see AuthLevel.Critical. 
     * When @see AuthLevel.None or @see AuthLevel.Unsafe, this is the Anonymous user information. 
     * */
    public get user(): IUserInfo { return this._level !== AuthLevel.Unsafe ? this._user : this._typeSystem.userInfo.anonymous }
    
    /** Gets the user information, regardless of the @see level. */
    public get unsafeUser(): IUserInfo { return this._user; }
    
    /** 
     * Gets the actual user information as long as the @see level is @see AuthLevel.Normal or @see AuthLevel.Critical. 
     * When @see AuthLevel.None or @see AuthLevel.Unsafe, this is the Anonymous user information. 
     * This actual user is not the same as this user if @see isImpersonated is true.
    */
    public get actualUser(): IUserInfo { return this._level !== AuthLevel.Unsafe ? this._actualUser : this._typeSystem.userInfo.anonymous }
   
    /** 
     * Gets the unsafe actual user information regardless of the @see level.  
     * This actual user is not the same as this user if @see isImpersonated is true.
    */
    public get unsafeActualUser(): IUserInfo { return this._actualUser; }

    /** 
     * Gets the expiration date. This is undefined if this information has already expired. 
     * This expires is guaranteed to be after (or equal to) criticalExpires.
    */
    public get expires(): Date|undefined { return this._expires; }

    /** 
     * Gets the critical expiration date. 
     * This is undefined if this information has no critical expiration date, ie. when level is not AuthLevel.Critical. 
     * When defined, this criticalExpires is guaranteed to be before (or equal to) expires.
     */
    public get criticalExpires(): Date|undefined { return this._criticalExpires; }

        
    /** 
     * Gets the device identifier. 
     * The empty string is the default (unset, unknown) device identifier.
     */
    public get deviceId(): string { return this._deviceId; }

    /** 
     * Gets whether an impersonation is active here: @see unsafeUser is not the same as the @see unsafeActualUser.
     * Note that @see user and @see actualUser may be both the Anonymous user if @see level is @see AuthLevel.None 
     * or @see AuthLevel.Unsafe.
     */
    public get isImpersonated(): boolean { return this._user !== this._actualUser; }

    /** Gets the authentication level. */
    public get level(): AuthLevel { return this._level; }

    /**
     * Initializes a new StdAuthenticationInfo. 
     * Note that expiration dates are checked against the utcNow parameter so that @see level is
     * automatically computed.
     * @param typeSystem Required type system.
     * @param actualUser Actual user information. May be null: resolves to the user parameter or the Anonymous user.
     * @param user User information. May be null: resolves to the user parameter or the Anonymous user.
     * @param expires Optional expires date.
     * @param criticalExpires Optional critical expiration date.
     * @param deviceId Optional device identifier.
     * @param utcNow The date to consider to challenge expires and criticalExpires parameters.
     */
    constructor(
        typeSystem: IAuthenticationInfoTypeSystem<IUserInfo>,
        actualUser: IUserInfo|null,
        user: IUserInfo|null,
        expires?: Date,
        criticalExpires?: Date,
        deviceId?: string,
        utcNow: Date = new Date(Date.now())
    ) {
        if (!typeSystem) { throw new Error('typeSystem must be defined'); }
        this._deviceId = deviceId || "";
        if (!user) {
            if (actualUser) user = actualUser;
            else user = actualUser = typeSystem.userInfo.anonymous;
        } else {
            if (!actualUser) actualUser = user;
        }

        let level: AuthLevel;
        if (actualUser.userId == 0) {
            user = actualUser;
            expires = undefined;
            criticalExpires = undefined;
            level = AuthLevel.None;
        } else {
            if (actualUser !== user && actualUser.userId === user.userId) { user = actualUser; }

            if (expires) { if (expires <= utcNow) expires = undefined; }

            if (!expires) {
                criticalExpires = undefined;
                level = AuthLevel.Unsafe;
            } else {
                if (criticalExpires) {
                    if (criticalExpires <= utcNow) criticalExpires = undefined;
                    else if (criticalExpires > expires) criticalExpires = expires;
                }
                level = criticalExpires ? AuthLevel.Critical : AuthLevel.Normal;
            }
        }

        this._typeSystem = typeSystem;
        this._user = user;
        this._actualUser = actualUser;
        this._expires = expires;
        this._criticalExpires = criticalExpires;
        this._level = level;
    }

    /**
     * Checks current expiration dates and returns this StdAuthenticationInfo or an updated one if changed.
     * @param utcNow The date to consider to challenge current @see expires and @see criticalExpires properties.
     */
    public checkExpiration(utcNow?: Date): IAuthenticationInfoImpl<IUserInfo> {
        utcNow = utcNow || new Date(Date.now());
        let level = this._level;
        if (level < AuthLevel.Normal 
            || (level === AuthLevel.Critical && this._criticalExpires!.getTime() > utcNow.getTime())) {
            return this;
        }
        // level is necessarily greater or equal to Normal. 
        if (this._expires!.getTime() > utcNow.getTime()) {
            if (level === AuthLevel.Normal) { return this; }
            return this.create(this._actualUser, this._user, this._expires, undefined, this._deviceId, utcNow);
        }

        return this.create(this._actualUser, this._user, undefined, undefined, this._deviceId, utcNow);
    }

     /**
     * Sets the expires date and checks its expiration based on utcNow parameter.
     * Returns this StdAuthenticationInfo or an updated one if changed.
     * Note that, by design, expires is necessarily before or equal to criticalExpires and this
     * method ensures this invariant.
     * @param expires The new expires value. Undefined to clear it (level is no more Normal nor Critical).
     * @param utcNow The date to consider to challenge expirations.
     */
    public setExpires(expires?: Date, utcNow?: Date): IAuthenticationInfoImpl<IUserInfo> {
        return this.areDateEquals(expires, this._expires)
            ? this.checkExpiration(utcNow)
            : this.create(this._actualUser, this._user, expires, this._criticalExpires, this._deviceId, utcNow);
    }

     /**
     * Sets the criticalExpires date and checks its expiration based on utcNow parameter.
     * Returns this StdAuthenticationInfo or an updated one if changed.
     * Note that, by design, expires is necessarily before or equal to criticalExpires and this
     * method ensures this invariant.
     * @param criticalExpires The new critical expires value. Undefined to clear it (level is no more Critical).
     * @param utcNow The date to consider to challenge expirations.
     */
    public setCriticalExpires(criticalExpires?: Date, utcNow?: Date): IAuthenticationInfoImpl<IUserInfo> {
        if (this.areDateEquals(criticalExpires, this._criticalExpires)) return this.checkExpiration(utcNow);
        
        let newExpires: Date|undefined = this._expires;
        if (criticalExpires && (!newExpires || newExpires.getTime() < criticalExpires.getTime())) {
            newExpires = criticalExpires;
        }

        return this.create(this._actualUser, this._user, newExpires, criticalExpires, this._deviceId, utcNow);
    }

    /**
     * Sets the device identifier (and checks expiration based on utcNow parameter).
     * Returns this StdAuthenticationInfo or an updated one if changed.
     * @param deviceId The new device identifier.
     * @param utcNow The date to consider to challenge expirations.
     */
    public setDeviceId(deviceId: string, utcNow?: Date): IAuthenticationInfoImpl<IUserInfo> {
        return this._deviceId ==  this._deviceId
            ? this.checkExpiration(utcNow)
            : this.create(this._actualUser, this._user, this._expires, this._criticalExpires, deviceId, utcNow);
    }

    /**
     * Returns a new StdAuthenticationInfo where the user may no more be the actualUser.
     * Note that the expiration dates are checked based on the utcNow parameter.
     * @param user Creates a new StdAuthenticationInfo where the user is changed.
     * @param utcNow The date to consider to challenge expirations.
     */
    public impersonate(user: IUserInfo, utcNow?: Date): IAuthenticationInfoImpl<IUserInfo> {
        user = user || this._typeSystem.userInfo.anonymous;
        if (this._actualUser.userId === 0) throw new Error('Invalid Operation');
        return this._user != user
            ? this.create(this._actualUser, user, this._expires, this._criticalExpires, this._deviceId, utcNow)
            : this.checkExpiration(utcNow);
    }

    /**
     * Returns a new StdAuthenticationInfo (or this one if isImpersonated is already false and
     * checkExpiration did not change anything) where the unsafeActualUser is the same as
     * the actualUser.
     * Note that the expiration dates are checked based on the utcNow parameter.
     * @param utcNow The date to consider to challenge expirations.
     */
    public clearImpersonation(utcNow?: Date): IAuthenticationInfoImpl<IUserInfo> {
        return this.isImpersonated
            ? this.create(this._actualUser, this._user, this._expires, this._criticalExpires, this._deviceId, utcNow)
            : this.checkExpiration(utcNow);
    }

   /**
     * Creates a new StdAuthenticationInfo bound to the same IAuthenticationInfoTypeSystem<T>. 
     * Note that expiration dates are checked against the utcNow parameter so that level is
     * automatically computed.
     * @param actualUser Actual user information. May be null: resolves to the user parameter or the Anonymous user.
     * @param user User information. May be null: resolves to the user parameter or the Anonymous user.
     * @param expires Optional expires date.
     * @param criticalExpires Optional critical expiration date.
     * @param deviceId Optional device identifier.
     * @param utcNow The date to consider to challenge expires and criticalExpires parameters.
     */
    protected create(actualUser: IUserInfo|null, user: IUserInfo|null, expires?: Date, criticalExpires?: Date, deviceId?: string, utcNow?: Date): IAuthenticationInfoImpl<IUserInfo> {
        return new StdAuthenticationInfo(this._typeSystem, actualUser, user, expires, criticalExpires, deviceId, utcNow);
    }

    private areDateEquals(firstDate?: Date, secondDate?: Date): boolean {
        if( !firstDate ) return !secondDate;
        if( !secondDate ) return false;
        return firstDate.getTime() === secondDate.getTime();
    }

    public toJSON() : Object {
        return { user: this.user, unsafeUser: this.unsafeUser, level: this.level, expires: this.expires, criticalExpires: this.criticalExpires, deviceId: this.deviceId, isImpersonated: this.isImpersonated, actualUser: this.actualUser };
    }
}
