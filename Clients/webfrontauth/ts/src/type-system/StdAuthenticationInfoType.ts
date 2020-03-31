import { IAuthenticationInfoType, IAuthenticationInfoTypeSystem, IAuthenticationInfoImpl, StdKeyType } from './type-system.model';
import { IUserInfo } from '../authService.model.public';
import { StdAuthenticationInfo } from './StdAuthenticationInfo';
import { IResponseInfo, IResponseScheme } from '../authService.model.private';

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
    public fromJson(o: {[index:string]: any}, availableSchemes?: ReadonlyArray<string>): IAuthenticationInfoImpl<IUserInfo>|null {
        if (!o) return null; 
        const user = this._typeSystem.userInfo.fromJson(o[StdKeyType.user], availableSchemes);
        // ActualUser may be null here.
        const actualUser = this._typeSystem.userInfo.fromJson(o[StdKeyType.actualUser], availableSchemes);
        const expires = this.parseOptionalDate(o[StdKeyType.expiration]);
        const criticalExpires = this.parseOptionalDate(o[StdKeyType.criticalExpiration]);
        return new StdAuthenticationInfo(this._typeSystem, actualUser, user, expires, criticalExpires);
    }

    private parseOptionalDate(s: string): Date|undefined {
        return s ? new Date(s) : undefined;
    }

    /**
     * Returns the authentication and available schemes previously saved by saveToLocalStorage.
     * @param storage Storage API to use.
     * @param endPoint The authentication end point. Informations are stored relatively to this end point. 
     * @param availableSchemes
     * The optional list of available schemes that are used to update the users' scheme's state (Unused/Active/Deprecated).
     * When specified (not null nor undefined), this parameter takes precedence over the schemes persisted in the local storage (if any).
     */
    public loadFromLocalStorage( storage: Storage,
                                 endPoint: string,
                                 availableSchemes? : ReadonlyArray<string> ) : [IAuthenticationInfoImpl<IUserInfo>|null,ReadonlyArray<string>] {
        const schemesS = storage.getItem( '$AuthSchemes$'+endPoint );
        const schemes = (availableSchemes === null || availableSchemes === undefined) 
                            ? (schemesS ? JSON.parse( schemesS ) : null)
                            : availableSchemes;
        
        const authInfoS = storage.getItem( '$AuthInfo$'+endPoint );
        if( authInfoS ) {
            let auth = this.fromJson( JSON.parse(authInfoS), schemes );
            if( auth ) auth = auth.clearImpersonation().setExpires();
            return [auth,schemes];
        }
        return [null,schemes];
    }

    /**
     * Generates a JSON string for the Authentication info.
     * @param auth The authentication information to serialize.
     */
    public toJson( auth: IAuthenticationInfoImpl<IUserInfo> ) : string {
        const o : IResponseInfo = 
        { 
            user: { 
                name: auth.unsafeUser.userName, 
                id: auth.unsafeUser.userId, 
                schemes: auth.unsafeUser.schemes.map( function( s ) { return { name: s.name, lastUsed: s.lastUsed }; } ) },
            exp: auth.expires,
            cexp: auth.criticalExpires
        };
        if( auth.isImpersonated ) {
            o.actualUser = {
                name: auth.unsafeActualUser.userName, 
                id: auth.unsafeActualUser.userId, 
                schemes: auth.unsafeActualUser.schemes.map( function( s ) { return { name: s.name, lastUsed: s.lastUsed }; 
                } )
            }
        }
        return JSON.stringify( o );
    }

    /**
     * Saves the authentication info and currently available schemes into the local storage.
     * @param storage Storage API to use.
     * @param endPoint The authentication end point. Informations are stored relatively to this end point. 
     * @param auth The authentication info to save. Null to remove current authentication information.
     * @param schemes Optional available schemes to save. By default, any existing persisted schemes are left as-is.
     */
    public saveToLocalStorage( storage: Storage, 
                               endPoint: string, 
                               auth: IAuthenticationInfoImpl<IUserInfo>|null, 
                               schemes?: ReadonlyArray<string> ) {
        if( schemes ) storage.setItem( '$AuthSchemes$'+endPoint, JSON.stringify( schemes ) );
        if( !auth )
        {
            storage.removeItem( '$AuthInfo$'+endPoint );
        }
        else
        {
            auth = auth.clearImpersonation().setExpires();
            storage.setItem( '$AuthInfo$'+endPoint, this.toJson( auth ) );
        }
    }

}
