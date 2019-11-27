import { IUserInfoType, StdKeyType } from './type-system.model';
import { IUserInfo, IUserSchemeInfo, SchemeUsageStatus } from '../authService.model.public';
import { StdUserInfo } from './StdUserInfo';
import { StdUserSchemeInfo } from './StdUserSchemeInfo';
import { IResponseScheme } from '../authService.model.private';

export class StdUserInfoType implements IUserInfoType<IUserInfo> {

    public get anonymous(): IUserInfo {
        return this.createAnonymous();
    }

    public create( userId: number, userName: string, schemes: IUserSchemeInfo[] = null ) {
        return new StdUserInfo( userId, userName, schemes );
    }

    public fromJson( o: object, availableSchemes: ReadonlyArray<string> ): IUserInfo {
        if( !o ) { return null; }

        function create( r: IResponseScheme, schemeNames: Set<string> ) : StdUserSchemeInfo {
            const name = r[ 'name' ];
            return new StdUserSchemeInfo( name, r[ 'lastUsed' ], schemeNames.delete( name ) 
                                                                    ? SchemeUsageStatus.Used 
                                                                    : SchemeUsageStatus.Deprecated );
        }

        let schemeNames = new Set<string>(availableSchemes);

        try {
            const userId = Number.parseInt( o[ StdKeyType.userId ] );
            if( userId === 0 ) { return this.anonymous; }
            const userName = o[ StdKeyType.userName ] as string;
            const schemes: IUserSchemeInfo[] = [];
            const jsonSchemes = o[ StdKeyType.schemes ] as IResponseScheme[];
            jsonSchemes.forEach( p => schemes.push( create( p, schemeNames ) ) );
            schemeNames.forEach( s => schemes.push( new StdUserSchemeInfo( s, new Date(0), SchemeUsageStatus.Unused ) ) );
            return new StdUserInfo( userId, userName, schemes );
        } catch( error ) {
            throw new Error( error );
        }
    }

    protected createAnonymous(): IUserInfo {
        return new StdUserInfo( 0, null, null );
    }
}
