import { IAuthenticationInfoType, IAuthenticationInfoTypeSystem, IAuthenticationInfoImpl, StdKeyType } from './type-system.model';
import { IUserInfo, IEndPoint } from '../authService.model.public';
import { StdAuthenticationInfo } from './StdAuthenticationInfo';

export class StdAuthenticationInfoType implements IAuthenticationInfoType<IUserInfo> {

    private readonly _typeSystem: IAuthenticationInfoTypeSystem<IUserInfo>;

    public get none(): IAuthenticationInfoImpl<IUserInfo> {
        return this.create(this._typeSystem.userInfo.anonymous);
    }

    constructor(
        typeSystem: IAuthenticationInfoTypeSystem<IUserInfo>
    ) {
        this._typeSystem = typeSystem;
    }

    public create(user: IUserInfo, expires?: Date, criticalExpires?: Date): IAuthenticationInfoImpl<IUserInfo> {
        return user === null
            ? this.none
            : new StdAuthenticationInfo(
                this._typeSystem,
                user,
                null,
                expires,
                criticalExpires
            );
    }

    /**
     * Maps an object (by parsing it) into a necessarily valid authentication info.
     * @param o Any object that must be shaped like an authentication info.
     * @param availableSchemes The optional list of available schemes. When empty, all user schemes' status is Active.
     */
    public fromJson(o: object, availableSchemes?: ReadonlyArray<string>): IAuthenticationInfoImpl<IUserInfo> {
        if (!o) { return null; }
        try {
            const user = this._typeSystem.userInfo.fromJson(o[StdKeyType.user], availableSchemes);
            const actualUser = this._typeSystem.userInfo.fromJson(o[StdKeyType.actualUser], availableSchemes);
            const expires = this.parseNullableDate(o[StdKeyType.expiration]);
            const criticalExpires = this.parseNullableDate(o[StdKeyType.criticalExpiration]);
            return new StdAuthenticationInfo(this._typeSystem, actualUser, user, expires, criticalExpires);
        } catch (error) {
            throw new Error(error);
        }
    }

    private parseNullableDate(s: string): Date {
        return s ? new Date(s) : null;
    }

    public loadFromLocalStorage( storage: Storage,
                                 endPoint: string,
                                 availableSchemes : ReadonlyArray<string> ) : [IAuthenticationInfoImpl<IUserInfo>,ReadonlyArray<string>] {
        const schemesS = storage.getItem( '$AuthSchemes$'+endPoint );
        const authInfoS = storage.getItem( '$AuthInfo$'+endPoint );
        if( authInfoS ) {
            if( !availableSchemes ) availableSchemes = schemesS ? JSON.parse( schemesS ) : [];
            let auth = this.fromJson( JSON.parse(authInfoS), availableSchemes )
                            .clearImpersonation()
                            .setExpires( new Date(0) );
            return [auth,availableSchemes];
        }
        return [null,availableSchemes];
    }

    public saveToLocalStorage( storage: Storage,
                               endPoint: string,
                               auth: IAuthenticationInfoImpl<IUserInfo>,
                               schemes: ReadonlyArray<string> ) {
        storage.setItem( '$AuthSchemes$'+endPoint, JSON.stringify( auth ) );
        if( schemes ) storage.setItem( '$AuthInfo$'+endPoint, JSON.stringify( schemes ) );
    }

}
