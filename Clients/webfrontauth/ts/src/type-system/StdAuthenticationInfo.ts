import { IUserInfo, AuthLevel } from '../authService.model.public';
import { IAuthenticationInfoTypeSystem, IAuthenticationInfoImpl } from './type-system.model';

export class StdAuthenticationInfo implements IAuthenticationInfoImpl<IUserInfo> {

    private readonly _typeSystem: IAuthenticationInfoTypeSystem<IUserInfo>;
    private readonly _user: IUserInfo;
    private readonly _actualUser: IUserInfo;
    private readonly _expires: Date;
    private readonly _criticalExpires: Date;
    private readonly _level: AuthLevel;

    public get user(): IUserInfo { return this._level !== AuthLevel.Unsafe ? this._user : this._typeSystem.userInfo.anonymous }
    public get unsafeUser(): IUserInfo { return this._user; }
    public get actualUser(): IUserInfo { return this._level !== AuthLevel.Unsafe ? this._actualUser : this._typeSystem.userInfo.anonymous }
    public get unsafeActualUser(): IUserInfo { return this._actualUser; }
    public get expires(): Date { return this._expires; }
    public get criticalExpires(): Date { return this._criticalExpires; }
    public get isImpersonated(): boolean { return this._user !== this._actualUser; }
    public get level(): AuthLevel { return this._level; }

    constructor(
        typeSystem: IAuthenticationInfoTypeSystem<IUserInfo>,
        actualUser: IUserInfo,
        user: IUserInfo,
        expires: Date,
        criticalExpires: Date,
        utcNow: Date = new Date(Date.now())
    ) {
        if (!typeSystem) { throw new Error('typeSystem must be defined'); }

        if (!user) {
            if (actualUser) user = actualUser;
            else user = actualUser = typeSystem.userInfo.anonymous;
        } else {
            if (!actualUser) actualUser = user;
        }

        let level: AuthLevel;
        if (actualUser.userId == 0) {
            user = actualUser;
            expires = null;
            criticalExpires = null;
            level = AuthLevel.None;
        } else {
            if (actualUser !== user && actualUser.userId === user.userId) { user = actualUser; }

            if (expires) { if (expires <= utcNow) expires = null; }

            if (!expires) {
                criticalExpires = null;
                level = AuthLevel.Unsafe;
            } else {
                if (criticalExpires) {
                    if (criticalExpires <= utcNow) criticalExpires = null;
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

    public checkExpiration(utcNow?: Date): IAuthenticationInfoImpl<IUserInfo> {
        utcNow = utcNow || new Date(Date.now());
        let level = this._level;
        if (level < AuthLevel.Normal || (level === AuthLevel.Critical && this._criticalExpires.getTime() > utcNow.getTime())) {
            return this;
        }

        if (this._expires.getTime() > utcNow.getTime()) {
            if (level === AuthLevel.Normal) { return this; }
            return this.clone(this._actualUser, this._user, this._expires, null, utcNow);
        }

        return this.clone(this._actualUser, this._user, null, null, utcNow);
    }

    public setExpires(expires: Date, utcNow?: Date): IAuthenticationInfoImpl<IUserInfo> {
        return this.areDateEquals(expires, this._expires)
            ? this.checkExpiration(utcNow)
            : this.clone(this._actualUser, this._user, expires, this._criticalExpires, utcNow);
    }

    public setCriticalExpires(criticalExpires: Date, utcNow?: Date): IAuthenticationInfoImpl<IUserInfo> {
        if (this.areDateEquals(criticalExpires, this._criticalExpires)) { return this.checkExpiration(utcNow); }

        let newExpires: Date = this._expires;
        if (criticalExpires && (!newExpires || newExpires.getTime() < criticalExpires.getTime())) {
            newExpires = criticalExpires;
        }

        return this.clone(this._actualUser, this._user, newExpires, criticalExpires, utcNow);
    }

    public impersonate(user: IUserInfo, utcNow?: Date): IAuthenticationInfoImpl<IUserInfo> {
        user = user || this._typeSystem.userInfo.anonymous;
        if (this._actualUser.userId === 0) throw new Error('Invalid Operation');
        return this._user != user
            ? this.clone(this._actualUser, user, this._expires, this._criticalExpires, utcNow)
            : this.checkExpiration(utcNow);
    }

    public clearImpersonation(utcNow?: Date): IAuthenticationInfoImpl<IUserInfo> {
        return this.isImpersonated
            ? this.clone(this._actualUser, this._user, this._expires, this._criticalExpires, utcNow)
            : this.checkExpiration(utcNow);
    }

    protected clone(actualUser: IUserInfo, user: IUserInfo, expires: Date, criticalExpires: Date, utcNow?: Date): IAuthenticationInfoImpl<IUserInfo> {
        return new StdAuthenticationInfo(this._typeSystem, actualUser, user, expires, criticalExpires, utcNow);
    }

    private areDateEquals(firstDate: Date, secondDate: Date): boolean {
        return firstDate === secondDate || (firstDate && secondDate && firstDate.getTime() === secondDate.getTime());
    }
}
