import { IUserInfo, IAuthenticationInfo, AuthLevel } from '../authService.model.public';
import { IAuthenticationInfoTypeSystem } from './type-system.model';

export class StdAuthenticationInfo implements IAuthenticationInfo {

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
        utcNow: Date = new Date( Date.now() )
    ) {
        if( !typeSystem ) { throw new Error( 'typeSystem must be defined' ); }

        if( !user )
        {
            if( actualUser ) user = actualUser;
            else user = actualUser = typeSystem.userInfo.anonymous;
        }
        else
        {
            if( !actualUser ) actualUser = user;
        }

        let level: AuthLevel;
        if( actualUser.userId == 0 )
        {
            user = actualUser;
            expires = null;
            criticalExpires = null;
            level = AuthLevel.None;
        }
        else 
        {
            if( actualUser !== user && actualUser.userId === user.userId )
            {
                user = actualUser;
            }

            if( expires )
            {
                if( expires <= utcNow ) expires = null;
            }

            if( !expires )
            {
                criticalExpires = null;
                level = AuthLevel.Unsafe;
            }
            else
            {
                if( criticalExpires )
                {
                    if( criticalExpires <= utcNow ) criticalExpires = null;
                    else if( criticalExpires > expires ) criticalExpires = expires;
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
}