import { IUserSchemeInfo, IUserInfo } from '../authService.model.public';

export class StdUserInfo implements IUserInfo {

    public static readonly emptySchemes: IUserSchemeInfo[] = [];

    private readonly _userId: number;
    private readonly _userName: string;
    private readonly _schemes: ReadonlyArray<IUserSchemeInfo>;

    /** Gets the user identifier. 0 for the Anonymous user. */
    public get userId(): number { return this._userId; }

    /** Gets the user name. This is the empty string for the Anonymous user. */
    public get userName(): string { return this._userName; }
    
    /** 
     * Gets the authentication schemes that this user has used to authenticate so far.
     * This is empty for Anonymous user.  
     */
    public get schemes(): ReadonlyArray<IUserSchemeInfo> { return this._schemes; }

    constructor( userId: number, userName: string, schemes?: ReadonlyArray<IUserSchemeInfo> ) {
        this._userId = userId;
        this._userName = userName;
        if( (this._userName.length === 0) !== (userId === 0) ) {
            throw new Error( `${this._userName} is empty if and only ${this._userId} is 0.`);
        }
        this._schemes = schemes ? schemes : StdUserInfo.emptySchemes;
    }
}