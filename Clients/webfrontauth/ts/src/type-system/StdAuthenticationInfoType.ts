import { IAuthenticationInfoType, IAuthenticationInfoTypeSystem, IAuthenticationInfoImpl } from './type-system.model';
import { IUserInfo, IAuthenticationInfo } from '../authService.model.public';
import { StdAuthenticationInfo, StdAuthenticationTypeSystem } from '.';

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

    public fromJson(o: object): IAuthenticationInfoImpl<IUserInfo> {
        if (!o) { return null; }
        try {
            const user = this._typeSystem.userInfo.fromJson(o[StdAuthenticationTypeSystem.userKeyType]);
            const actualUser = this._typeSystem.userInfo.fromJson(o[StdAuthenticationTypeSystem.actualUserKeyType]);
            const expires = this.parseNullableDate(o[StdAuthenticationTypeSystem.expirationKeyType]);
            const criticalExpires = this.parseNullableDate(o[StdAuthenticationTypeSystem.criticalExpirationKeyType]);
            return new StdAuthenticationInfo(this._typeSystem, actualUser, user, expires, criticalExpires);
        } catch (error) {
            throw new Error(error);
        }
    }

    private parseNullableDate(s: string): Date {
        return s ? new Date(s) : null;
    }
}
