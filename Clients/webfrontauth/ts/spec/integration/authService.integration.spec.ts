import { expect } from 'chai';
import axios from 'axios';
import * as tough from 'tough-cookie';
import axiosCookieJarSupport from 'axios-cookiejar-support';

import {
    AuthService,
    IAuthenticationInfo,
    AuthLevel,
    IUserInfo
} from '../../';
import { areUserInfoEquals, areAuthenticationInfoEquals } from '../helpers/test-helpers';

/*
 * These tests require a webfrontauth() in order to run them.
 * It needs to have:
 *  - Basic login enabled with one user matching the following pattern:
 *      {
 *          name: 'admin',
 *          password: 'admin'
 *      }
 *  - A not null sliding expiration
 */
describe('AuthService', function() {
    let authService: AuthService;

    const anonymous: IUserInfo = {
        userId: 0,
        userName: '',
        schemes: []
    };

    const logoutModel: IAuthenticationInfo = {
        user: anonymous,
        unsafeUser: anonymous,
        actualUser: anonymous,
        unsafeActualUser: anonymous,
        expires: undefined,
        criticalExpires: undefined,
        isImpersonated: false,
        level: AuthLevel.None
    };

    before(async function() {
        const axiosInstance = axios.create();
        axiosCookieJarSupport(axiosInstance);
        const cookieJar = new tough.CookieJar();
        axiosInstance.defaults.jar = cookieJar;

        const identityEndPoint = {
            hostname: 'localhost',
            port: 27459,
            disableSsl: true
        };

        authService = await AuthService.createAsync( { identityEndPoint }, axiosInstance );
    });

    beforeEach(async function() {
        await authService.logout(true);
    });

    it('should basicLogin and logout.', async function() {
        await authService.basicLogin('admin', 'admin');
        let currentModel: IAuthenticationInfo = authService.authenticationInfo;
        expect(currentModel.user.userName).to.be.equal('admin');
        expect(currentModel.unsafeUser.userName).to.be.equal('admin');
        expect(currentModel.actualUser.userName).to.be.equal('admin');
        expect(currentModel.unsafeActualUser.userName).to.be.equal('admin');
        expect(currentModel.isImpersonated).to.be.false;
        expect(currentModel.level).to.be.equal(AuthLevel.Normal);
        expect(authService.token).to.not.be.equal('');
        expect(authService.refreshable).to.be.true;

        await authService.logout();
        currentModel = authService.authenticationInfo;
        expect(areUserInfoEquals(currentModel.user, anonymous)).to.be.true;
        expect(currentModel.unsafeUser.userName).to.be.equal('admin');
        expect(areUserInfoEquals(currentModel.actualUser, anonymous)).to.be.true;
        expect(currentModel.unsafeActualUser.userName).to.be.equal('admin');
        expect(currentModel.isImpersonated).to.be.false;
        expect(currentModel.level).to.be.equal(AuthLevel.Unsafe);
        expect(authService.token).to.not.be.equal('');
        expect(authService.refreshable).to.be.false;

        await authService.logout(true);
        expect(areAuthenticationInfoEquals(authService.authenticationInfo, logoutModel)).to.be.true;
        expect(authService.token).to.be.equal('');
        expect(authService.refreshable).to.be.false;
    });

    it('should refresh correctly.', async function() {
        await authService.refresh();
        let currentModel: IAuthenticationInfo = authService.authenticationInfo;

        await authService.basicLogin('admin', 'admin');
        currentModel = authService.authenticationInfo;
        expect(currentModel.user.userName).to.be.equal('admin');
        expect(currentModel.unsafeUser.userName).to.be.equal('admin');
        expect(currentModel.actualUser.userName).to.be.equal('admin');
        expect(currentModel.unsafeActualUser.userName).to.be.equal('admin');
        expect(currentModel.isImpersonated).to.be.false;
        expect(currentModel.level).to.be.equal(AuthLevel.Normal);
        expect(authService.token).to.not.be.equal('');
        expect(authService.refreshable).to.be.true;

        await authService.refresh();
        currentModel = authService.authenticationInfo;
        expect(currentModel.user.userName).to.be.equal('admin');
        expect(currentModel.unsafeUser.userName).to.be.equal('admin');
        expect(currentModel.actualUser.userName).to.be.deep.equal('admin');
        expect(currentModel.unsafeActualUser.userName).to.be.equal('admin');
        expect(currentModel.isImpersonated).to.be.false;
        expect(currentModel.level).to.be.equal(AuthLevel.Normal);
        expect(authService.token).to.not.be.equal('');
        expect(authService.refreshable).to.be.true;

        await authService.logout();
        currentModel = authService.authenticationInfo;
        expect(areUserInfoEquals(currentModel.user, anonymous)).to.be.true;
        expect(currentModel.unsafeUser.userName).to.be.equal('admin');
        expect(areUserInfoEquals(currentModel.actualUser, anonymous)).to.be.true;
        expect(currentModel.unsafeActualUser.userName).to.be.equal('admin');
        expect(currentModel.isImpersonated).to.be.false;
        expect(currentModel.level).to.be.equal(AuthLevel.Unsafe);
        expect(authService.token).to.not.be.equal('');
        expect(authService.refreshable).to.be.false;

        await authService.logout(true);
        expect(areAuthenticationInfoEquals(authService.authenticationInfo, logoutModel)).to.be.true;
        expect(authService.token).to.be.equal('');
        expect(authService.refreshable).to.be.false;
    });

    it('should call OnChange() correctly.', async function() {
        let authenticationInfo: IAuthenticationInfo = authService.authenticationInfo;
        const onChangeFunction = () => authenticationInfo = authService.authenticationInfo;
        authService.addOnChange(onChangeFunction);
        await authService.basicLogin('admin','admin');
        expect(areUserInfoEquals(authenticationInfo.user, anonymous)).to.be.false;
        await authService.logout();
        expect(areUserInfoEquals(authenticationInfo.user, anonymous)).to.be.true;

        authService.removeOnChange(onChangeFunction);
        await authService.basicLogin('admin','admin');
        expect(areUserInfoEquals(authenticationInfo.user, anonymous)).to.be.true;
    });

    it('should call OnChange() for every subscribed functions.', async function() {
        const booleanArray: boolean[] = [false, false, false];
        const functionArray: (() => void)[] = [];

        for(let i=0; i<booleanArray.length; ++i) functionArray.push(function() { booleanArray[i] = true; });
        functionArray.forEach(func => authService.addOnChange(() => func()));

        await authService.logout();
        booleanArray.forEach(bool => expect(bool).to.be.true);

        functionArray.forEach(func => authService.removeOnChange(() => func()));
    });
});
