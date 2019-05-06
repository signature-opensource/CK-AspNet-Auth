import { IUserSchemeInfo } from '../authService.model.public';

export class StdUserSchemeInfo implements IUserSchemeInfo {

    private readonly _name: string;
    private readonly _lastUsed: Date;

    public get name(): string { return this._name; }
    public get lastUsed(): Date { return this._lastUsed; }

    constructor( name: string, lastUsed: Date ) {
        this._name = name;
        this._lastUsed = lastUsed;
    }
}