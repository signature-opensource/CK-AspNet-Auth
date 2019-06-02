import { IUserSchemeInfo, IUserInfo } from '../authService.model.public';

export class StdUserInfo implements IUserInfo {

    public static emptySchemes: IUserSchemeInfo[] = [];

    private readonly _userId: number;
    private readonly _userName: string;
    private readonly _schemes: IUserSchemeInfo[];

    public get userId(): number { return this._userId; }
    public get userName(): string { return this._userName; }
    public get schemes(): IUserSchemeInfo[] { return this._schemes; }

    constructor( userId: number, userName: string, schemes: IUserSchemeInfo[] = null ) {
        this._userId = userId;
        this._userName = userName ? userName : '';
        if( (this._userName.length === 0) !== (userId === 0) ) {
            throw new Error( `${this._userName} is empty if and only ${this._userId} is 0.`);
        }
        this._schemes = schemes ? schemes : StdUserInfo.emptySchemes;
    }
}