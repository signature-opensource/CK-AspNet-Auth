import { IUserInfo, IAuthenticationInfo } from '../..';

export function areUserInfoEquals( userInfo1: IUserInfo, userInfo2: IUserInfo ): boolean {
    if( userInfo1 === userInfo2 ) { return true; }
    if( !userInfo1 || !userInfo2 ) { return false; }
    if( userInfo1.userId !== userInfo2.userId || userInfo1.userName !== userInfo2.userName ) { return false; }
    const s1 = userInfo1.schemes;
    const s2 = userInfo2.schemes;
    if( s1.length !== s2.length ) { return false; }
    if( s1.length > 0 ) {
        for( let i = 0; i < s1.length; ++i ) {
            if( s1[i].name !== s2[i].name 
                || s1[i].lastUsed.getDate() !== s2[i].lastUsed.getDate()
                || s1[i].status !== s2[i].status ) {
                return false;
            }
        }
    }
    return true;
}

export function areAuthenticationInfoEquals( info1: IAuthenticationInfo, info2: IAuthenticationInfo ): boolean {
    if( info1 === info2 ) { return true; }
    if( !info1 || !info2 ) { return false; }
    if( !areUserInfoEquals(info1.user, info2.user) ) { return false; }
    if( !areUserInfoEquals(info1.unsafeUser, info2.unsafeUser) ) { return false; }
    if( !areUserInfoEquals(info1.actualUser, info2.actualUser) ) { return false; }
    if( !areUserInfoEquals(info1.unsafeActualUser, info2.unsafeActualUser) ) { return false; }
    if( info1.expires !== info2.expires ) { return false; }
    if( info1.criticalExpires !== info2.criticalExpires ) { return false; }
    if( info1.isImpersonated !== info2.isImpersonated ) { return false; }
    if( info1.level !== info2.level ) { return false; }
    return true;
}