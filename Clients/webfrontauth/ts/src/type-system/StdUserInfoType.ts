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
     * @param availableSchemes
     * The optional list of available schemes that are used to update the user's scheme's state (Unused/Active/Deprecated). 
     * When unspecified (null or undefined), all user schemes' status are Active.
     * When empty, we consider that no schemes are actually available: all user schemes' status are Deprecated.
     */
    public fromJson( o: {[index: string]: any}, availableSchemes?: ReadonlyArray<string> ): IUserInfo|null {
        if( !o ) { return null; }

        function create( r: {[index: string]: any}, schemeNames: Set<string>|null ) : StdUserSchemeInfo {
            return new StdUserSchemeInfo( r.name, r.lastUsed, schemeNames === null || schemeNames.delete( r.name ) 
                                                                    ? SchemeUsageStatus.Active 
                                                                    : SchemeUsageStatus.Deprecated );
        }

        let schemeNames = (availableSchemes === null || availableSchemes === undefined) ? null : new Set<string>(availableSchemes);

        const userId = Number.parseInt( o[ StdKeyType.userId ] );
        if( userId === 0 ) { return this.anonymous; }
        const userName = o[ StdKeyType.userName ] as string;
        const schemes: IUserSchemeInfo[] = [];
        const jsonSchemes = o[ StdKeyType.schemes ] as {[index: string]: any}[];
        jsonSchemes.forEach( p => schemes.push( create( p, schemeNames ) ) );
        if( schemeNames ) schemeNames.forEach( s => schemes.push( new StdUserSchemeInfo( s, new Date(0), SchemeUsageStatus.Unused ) ) );
        return new StdUserInfo( userId, userName, schemes );       
    }

    protected createAnonymous(): IUserInfo {
        return new StdUserInfo( 0, '', [] );
    }
}
