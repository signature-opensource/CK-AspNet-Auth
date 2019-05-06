import { IAuthenticationInfoTypeSystem, IUserInfoType, IAuthenticationInfoType } from './type-system.model';
import { StdUserInfoType } from './StdUserInfoType';
import { StdAuthenticationInfoType } from './StdAuthenticationInfoType';
import { IUserInfo } from '../authService.model.public';

export class StdAuthenticationTypeSystem implements IAuthenticationInfoTypeSystem<IUserInfo> {

    private readonly _userInfo: IUserInfoType<IUserInfo>;
    private readonly _authenticationInfo: IAuthenticationInfoType<IUserInfo>;

    public get userInfo(): IUserInfoType<IUserInfo> { return this._userInfo; }
    public get authenticationInfo(): IAuthenticationInfoType<IUserInfo> { return this._authenticationInfo; }

    public static readonly userNameKeyType: string = 'name';
    public static readonly userIdKeyType: string = 'id';
    public static readonly schemesKeyType: string = 'schemes';
    public static readonly expirationKeyType: string = 'exp';
    public static readonly criticalExpirationKeyType: string = 'cexp';
    public static readonly userKeyType: string = 'user';
    public static readonly actualUserKeyType: string = 'actualUser';

    constructor()
    {
        this._userInfo = new StdUserInfoType();
        this._authenticationInfo = new StdAuthenticationInfoType( this );
    }
}