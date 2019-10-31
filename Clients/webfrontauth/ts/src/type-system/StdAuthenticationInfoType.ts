import { IAuthenticationInfoType, IAuthenticationInfoTypeSystem, IAuthenticationInfoImpl, StdKeyType } from './type-system.model';
import { IUserInfo } from '../authService.model.public';
import { StdAuthenticationInfo } from './StdAuthenticationInfo';

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
            const user = this._typeSystem.userInfo.fromJson(o[StdKeyType.user]);
            const actualUser = this._typeSystem.userInfo.fromJson(o[StdKeyType.actualUser]);
            const expires = this.parseNullableDate(o[StdKeyType.expiration]);
            const criticalExpires = this.parseNullableDate(o[StdKeyType.criticalExpiration]);
            return new StdAuthenticationInfo(this._typeSystem, actualUser, user, expires, criticalExpires);
        } catch (error) {
            throw new Error(error);
        }
    }

    private parseNullableDate(s: string): Date {
        return s ? new Date(s) : null;
    }
}
