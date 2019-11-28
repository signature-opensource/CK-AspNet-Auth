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
     * Maps an object (by parsing it) into a necessarily valid authentication info or null if
     * the given object o is false-ish.
     * @param o Any object that must be shaped like an authentication info.
     * @param availableSchemes The optional list of available schemes. When empty, all user schemes' status is Active.
     */
    public fromJson(o: object, availableSchemes?: ReadonlyArray<string>): IAuthenticationInfoImpl<IUserInfo>|null {
        if (!o) { return null; }
        try {
            const user = this._typeSystem.userInfo.fromJson(o[StdKeyType.user], availableSchemes);
            const actualUser = this._typeSystem.userInfo.fromJson(o[StdKeyType.actualUser], availableSchemes);
            const expires = this.parseOptionalDate(o[StdKeyType.expiration]);
            const criticalExpires = this.parseOptionalDate(o[StdKeyType.criticalExpiration]);
            return new StdAuthenticationInfo(this._typeSystem, actualUser, user, expires, criticalExpires);
        } catch (error) {
            throw new Error(error);
        }
    }

    private parseOptionalDate(s: string): Date|undefined {
        return s ? new Date(s) : undefined;
    }

    public loadFromLocalStorage( storage: Storage,
                                 endPoint: string,
                                 availableSchemes : ReadonlyArray<string> ) : [IAuthenticationInfoImpl<IUserInfo>|null,ReadonlyArray<string>] {
        const schemesS = storage.getItem( '$AuthSchemes$'+endPoint );
        const authInfoS = storage.getItem( '$AuthInfo$'+endPoint );
        if( authInfoS ) {
            if( !availableSchemes ) availableSchemes = schemesS ? JSON.parse( schemesS ) : [];
            let auth = this.fromJson( JSON.parse(authInfoS), availableSchemes );
            if( auth ) auth = auth.clearImpersonation().setExpires();
            return [auth,availableSchemes];
        }
        return [null,availableSchemes];
    }

    /**
     * Saves the authentication info and currently available schemes into the local storage.
     * @param storage Storage API to use.
     * @param endPoint The authentication end point.  
     * @param auth The authentication info to save. Null to remove current authentication information.
     * @param schemes Optional available schemes to save.
     */
    public saveToLocalStorage( storage: Storage, 
                               endPoint: string, 
                               auth: IAuthenticationInfoImpl<IUserInfo>|null, 
                               schemes?: ReadonlyArray<string> ) {
        if( !auth )
        {
            storage.removeItem( '$AuthInfo$'+endPoint );
        }
        else
        {
            auth = auth.clearImpersonation().setExpires( new Date(0) );
            storage.setItem( '$AuthInfo$'+endPoint, JSON.stringify( auth ) );
        }
        if( schemes ) storage.setItem( '$AuthSchemes$'+endPoint, JSON.stringify( schemes ) );
    }

}
