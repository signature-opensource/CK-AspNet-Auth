import { IUserInfoType } from './type-system.model';
import { IUserInfo, IUserSchemeInfo } from '../authService.model.public';
import { StdAuthenticationTypeSystem } from './StdAuthenticationTypeSystem';
import { StdUserInfo } from './StdUserInfo';
import { StdUserSchemeInfo } from './StdUserSchemeInfo';

export class StdUserInfoType implements IUserInfoType<IUserInfo> {
    
    public get anonymous(): IUserInfo {
        return this.createAnonymous();
    }
    
    public create( userId: number, userName: string, schemes: IUserSchemeInfo[] = null ) {
        return new StdUserInfo( userId, userName, schemes );
    }

    public fromJson( o: object ): IUserInfo {
        if( !o ) { return null; }
        try {
            const userId = Number.parseInt( o[ StdAuthenticationTypeSystem.userIdKeyType ] );
            if( userId === 0 ) { return this.anonymous; }
            const userName = <string> o[ StdAuthenticationTypeSystem.userNameKeyType ];
            const schemes = [];
            const t = o[ StdAuthenticationTypeSystem.schemesKeyType ];
            t.forEach( p => schemes.push( new StdUserSchemeInfo( p[ 'name' ], new Date( p['lastUsed'] ) ) ) );
            return new StdUserInfo( userId, userName, schemes );
        } catch( error ) {
            throw new Error( error );
        }
    }

    protected createAnonymous(): IUserInfo {
        return new StdUserInfo( 0, null, null );
    }
}