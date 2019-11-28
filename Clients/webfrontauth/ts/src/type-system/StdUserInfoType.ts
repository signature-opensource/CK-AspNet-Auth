import { IUserInfoType, StdKeyType } from './type-system.model';
import { IUserInfo, IUserSchemeInfo, SchemeUsageStatus } from '../authService.model.public';
import { StdUserInfo } from './StdUserInfo';
import { StdUserSchemeInfo } from './StdUserSchemeInfo';
import { IResponseScheme } from '../authService.model.private';

export class StdUserInfoType implements IUserInfoType<IUserInfo> {

    public get anonymous(): IUserInfo {
        return this.createAnonymous();
    }

    public create( userId: number, userName: string, schemes: ReadonlyArray<IUserSchemeInfo> ) {
        return new StdUserInfo( userId, userName, schemes );
    }

    /**
     * Maps an object (by parsing it) into a necessarily valid user info or null if
     * the given object o is false-ish.
     * @param o Any object that must be shaped like a T.
     * @param availableSchemes The optional list of available schemes. When empty, all user schemes' status is Active.
     */
    public fromJson( o: object, availableSchemes?: ReadonlyArray<string> ): IUserInfo|null {
        if( !o ) { return null; }

        function create( r: IResponseScheme, schemeNames: Set<string>|null ) : StdUserSchemeInfo {
            const name = r[ 'name' ];
            return new StdUserSchemeInfo( name, r[ 'lastUsed' ], schemeNames === null || schemeNames.delete( name ) 
                                                                    ? SchemeUsageStatus.Active 
                                                                    : SchemeUsageStatus.Deprecated );
        }

        let schemeNames = availableSchemes ? new Set<string>(availableSchemes) : null;

        try {
            const userId = Number.parseInt( o[ StdKeyType.userId ] );
            if( userId === 0 ) { return this.anonymous; }
            const userName = o[ StdKeyType.userName ] as string;
            const schemes: IUserSchemeInfo[] = [];
            const jsonSchemes = o[ StdKeyType.schemes ] as IResponseScheme[];
            jsonSchemes.forEach( p => schemes.push( create( p, schemeNames ) ) );
            if( schemeNames ) schemeNames.forEach( s => schemes.push( new StdUserSchemeInfo( s, new Date(0), SchemeUsageStatus.Unused ) ) );
            return new StdUserInfo( userId, userName, schemes );
        } catch( error ) {
            throw new Error( error );
        }
    }

    protected createAnonymous(): IUserInfo {
        return new StdUserInfo( 0, '', [] );
    }
}
