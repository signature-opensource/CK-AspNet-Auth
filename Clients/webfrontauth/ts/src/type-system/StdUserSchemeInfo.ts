import { IUserSchemeInfo, SchemeUsageStatus } from '../authService.model.public';

export class StdUserSchemeInfo implements IUserSchemeInfo {

    private readonly _name: string;
    private readonly _lastUsed: Date;
    private readonly _status: SchemeUsageStatus;

    public get name(): string { return this._name; }
    public get lastUsed(): Date { return this._lastUsed; }
    public get status(): SchemeUsageStatus { return this._status; }

    constructor( name: string, lastUsed: Date|string, status: SchemeUsageStatus ) {
        this._name = name;
        this._lastUsed = lastUsed  instanceof Date ? lastUsed : new Date( Date.parse( lastUsed ) );
        this._status = status;
    }

    public toJSON() {
        return { name: this.name, lastUsed: this.lastUsed, status: this.status };
    }
}