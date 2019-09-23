import { expect } from 'chai';
import axios, { AxiosRequestConfig, AxiosResponse, AxiosError } from 'axios';

import {
    AuthService,
    IAuthenticationInfo,
    AuthLevel,
    IUserInfo,
    IAuthServiceConfiguration
} from '../../';
import { AuthServiceConfiguration, IWebFrontAuthResponse } from '../../src/index.private';
import { areUserInfoEquals } from '../helpers/test-helpers';
import { WebFrontAuthError } from '../../src/index.extension';
import ResponseBuilder from '../helpers/response-builder';

describe('AuthService', function () {
    const axiosInstance = axios.create({ timeout: 0.1 });
    let requestInterceptorId: number;
    let responseInterceptorId: number;

    const authService = new AuthService({ identityEndPoint: {} }, axiosInstance);
    const emptyResponse: IWebFrontAuthResponse = {
        info: null,
        token: null,
        refreshable: false
    }
    let serverResponse: IWebFrontAuthResponse = emptyResponse;

    const schemeLastUsed = new Date();
    const exp = new Date();
    exp.setHours(exp.getHours() + 6);
    const cexp = new Date();
    cexp.setHours(cexp.getHours() + 3);

    const anonymous: IUserInfo = {
        userId: 0,
        userName: '',
        schemes: []
    };

    before(function () {
        requestInterceptorId = axiosInstance.interceptors.request.use((config: AxiosRequestConfig) => {
            return config;
        });

        responseInterceptorId = axiosInstance.interceptors.response.use((response: AxiosResponse) => {
            return response; // Never occurs
        }, (error: AxiosError) => {
            return Promise.resolve({
                data: serverResponse,
                status: 200,
                statusText: 'Ok',
                headers: {},
                config: error.config
            });
        });
    });

    beforeEach(async function () {
        serverResponse = emptyResponse;
        await authService.logout(true);
    });

    after(function () {
        axiosInstance.interceptors.request.eject(requestInterceptorId);
        axiosInstance.interceptors.response.eject(responseInterceptorId);
    });

    it('should parse configuration object correctly.', function () {
        let configuration: IAuthServiceConfiguration = { identityEndPoint: { hostname: 'host', disableSsl: false, port: 12345 } };

        let authConfiguration: AuthServiceConfiguration = new AuthServiceConfiguration(configuration);
        expect(authConfiguration.webFrontAuthEndPoint).to.be.equal('https://host:12345/');

        configuration = { identityEndPoint: {} };
        authConfiguration = new AuthServiceConfiguration(configuration);
        expect(authConfiguration.webFrontAuthEndPoint).to.be.equal('/');
    });

    context('when parsing server response', function () {

        it('should parse basicLogin response.', async function () {

            const expectedLoginInfo: IUserInfo = {
                userId: 2,
                userName: 'Alice',
                schemes: [{ name: 'Basic', lastUsed: schemeLastUsed }]
            }

            serverResponse = new ResponseBuilder()
                .withLoginFailure({ loginFailureCode: 4, loginFailureReason: 'Invalid credentials.' })
                .build();
            await authService.basicLogin('', '');

            expect(areUserInfoEquals(authService.authenticationInfo.user, anonymous)).to.be.true;
            expect(areUserInfoEquals(authService.authenticationInfo.unsafeUser, anonymous)).to.be.true;
            expect(areUserInfoEquals(authService.authenticationInfo.actualUser, anonymous)).to.be.true;
            expect(areUserInfoEquals(authService.authenticationInfo.unsafeActualUser, anonymous)).to.be.true;
            expect(authService.authenticationInfo.level).to.be.equal(AuthLevel.None);
            expect(authService.token).to.be.equal('');
            expect(authService.refreshable).to.be.equal(false);
            expect(authService.currentError).to.deep.equal(new WebFrontAuthError({
                loginFailureCode: 4,
                loginFailureReason: 'Invalid credentials.'
            }));

            serverResponse = new ResponseBuilder()
                .withUser({ id: 2, name: 'Alice', schemes: [{ name: 'Basic', lastUsed: schemeLastUsed }] })
                .withToken('CfDJ8CS62…pLB10X')
                .build();
            await authService.basicLogin('', '');

            expect(areUserInfoEquals(authService.authenticationInfo.user, anonymous)).to.be.true;
            expect(areUserInfoEquals(authService.authenticationInfo.unsafeUser, expectedLoginInfo)).to.be.true;
            expect(areUserInfoEquals(authService.authenticationInfo.actualUser, anonymous)).to.be.true;
            expect(areUserInfoEquals(authService.authenticationInfo.unsafeActualUser, expectedLoginInfo)).to.be.true;
            expect(authService.authenticationInfo.level).to.be.equal(AuthLevel.Unsafe);
            expect(authService.token).to.be.equal('CfDJ8CS62…pLB10X');
            expect(authService.refreshable).to.be.equal(false);
            expect(authService.currentError.error).to.equal(null);

            serverResponse = new ResponseBuilder()
                .withUser({ id: 2, name: 'Alice', schemes: [{ name: 'Basic', lastUsed: schemeLastUsed }] })
                .withExpires(exp)
                .withToken('CfDJ8CS62…pLB10X')
                .withRefreshable(true)
                .build();
            await authService.basicLogin('', '');

            expect(areUserInfoEquals(authService.authenticationInfo.user, expectedLoginInfo)).to.be.true;
            expect(areUserInfoEquals(authService.authenticationInfo.unsafeUser, expectedLoginInfo)).to.be.true;
            expect(areUserInfoEquals(authService.authenticationInfo.actualUser, expectedLoginInfo)).to.be.true;
            expect(areUserInfoEquals(authService.authenticationInfo.unsafeActualUser, expectedLoginInfo)).to.be.true;
            expect(authService.authenticationInfo.level).to.be.equal(AuthLevel.Normal);
            expect(authService.token).to.be.equal('CfDJ8CS62…pLB10X');
            expect(authService.refreshable).to.be.equal(true);
            expect(authService.currentError.error).to.equal(null);
        });

        it('should parse refresh response.', async function () {
            const loginInfo: IUserInfo = {
                userId: 2,
                userName: 'Alice',
                schemes: [{ name: 'Basic', lastUsed: schemeLastUsed }]
            }

            serverResponse = new ResponseBuilder()
                .withUser({ id: 2, name: 'Alice', schemes: [{ name: 'Basic', lastUsed: schemeLastUsed }] })
                .withExpires(exp)
                .withToken('CfDJ8CS62…pLB10X')
                .withRefreshable(true)
                .build();
            await authService.basicLogin('', '');

            serverResponse = new ResponseBuilder()
                .withUser({ id: 2, name: 'Alice', schemes: [{ name: 'Basic', lastUsed: schemeLastUsed }] })
                .withExpires(exp)
                .withToken('CfDJ8CS62…pLB10X')
                .withRefreshable(false)
                .withVersion('v0.0.0-alpha')
                .build();
            await authService.refresh();

            expect(areUserInfoEquals(authService.authenticationInfo.user, loginInfo)).to.be.true;
            expect(areUserInfoEquals(authService.authenticationInfo.unsafeUser, loginInfo)).to.be.true;
            expect(areUserInfoEquals(authService.authenticationInfo.actualUser, loginInfo)).to.be.true;
            expect(areUserInfoEquals(authService.authenticationInfo.unsafeActualUser, loginInfo)).to.be.true;
            expect(authService.authenticationInfo.level).to.be.equal(AuthLevel.Normal);
            expect(authService.token).to.be.equal('CfDJ8CS62…pLB10X');
            expect(authService.refreshable).to.be.equal(false);
            expect(authService.currentError.error).to.equal(null);
            expect(authService.version).to.be.equal('v0.0.0-alpha');

            serverResponse = new ResponseBuilder()
                .withUser({ id: 2, name: 'Alice', schemes: [{ name: 'Basic', lastUsed: schemeLastUsed }] })
                .withToken('CfDJ8CS62…pLB10X')
                .withRefreshable(false)
                .build();
            await authService.refresh();

            expect(areUserInfoEquals(authService.authenticationInfo.user, anonymous)).to.be.true;
            expect(areUserInfoEquals(authService.authenticationInfo.unsafeUser, loginInfo)).to.be.true;
            expect(areUserInfoEquals(authService.authenticationInfo.actualUser, anonymous)).to.be.true;
            expect(areUserInfoEquals(authService.authenticationInfo.unsafeActualUser, loginInfo)).to.be.true;
            expect(authService.authenticationInfo.level).to.be.equal(AuthLevel.Unsafe);
            expect(authService.token).to.be.equal('CfDJ8CS62…pLB10X');
            expect(authService.refreshable).to.be.equal(false);
            expect(authService.currentError.error).to.equal(null);

            serverResponse = emptyResponse;
            await authService.refresh();

            expect(areUserInfoEquals(authService.authenticationInfo.user, anonymous)).to.be.true;
            expect(areUserInfoEquals(authService.authenticationInfo.unsafeUser, anonymous)).to.be.true;
            expect(areUserInfoEquals(authService.authenticationInfo.actualUser, anonymous)).to.be.true;
            expect(areUserInfoEquals(authService.authenticationInfo.unsafeActualUser, anonymous)).to.be.true;
            expect(authService.authenticationInfo.level).to.be.equal(AuthLevel.None);
            expect(authService.token).to.be.equal('');
            expect(authService.refreshable).to.be.equal(false);
            expect(authService.currentError.error).to.equal(null);
        });

        it('should parse logout response.', async function () {
            const loginInfo: IUserInfo = {
                userId: 2,
                userName: 'Alice',
                schemes: [{ name: 'Basic', lastUsed: schemeLastUsed }]
            }

            serverResponse = new ResponseBuilder()
                .withUser({ id: 2, name: 'Alice', schemes: [{ name: 'Basic', lastUsed: schemeLastUsed }] })
                .withExpires(exp)
                .withToken('CfDJ8CS62…pLB10X')
                .withRefreshable(true)
                .build();
            await authService.basicLogin('', '');

            expect(areUserInfoEquals(authService.authenticationInfo.user, loginInfo)).to.be.true;
            expect(areUserInfoEquals(authService.authenticationInfo.unsafeUser, loginInfo)).to.be.true;
            expect(areUserInfoEquals(authService.authenticationInfo.actualUser, loginInfo)).to.be.true;
            expect(areUserInfoEquals(authService.authenticationInfo.unsafeActualUser, loginInfo)).to.be.true;
            expect(authService.authenticationInfo.level).to.be.equal(AuthLevel.Normal);
            expect(authService.token).to.be.equal('CfDJ8CS62…pLB10X');
            expect(authService.refreshable).to.be.equal(true);
            expect(authService.currentError.error).to.be.equal(null);

            // We set the response for the refresh which is triggered by the logout
            serverResponse = new ResponseBuilder()
                .withUser({ id: 2, name: 'Alice', schemes: [{ name: 'Basic', lastUsed: schemeLastUsed }] })
                .withToken('CfDJ8CS62…pLB10X')
                .withRefreshable(false)
                .build();
            await authService.logout();

            expect(areUserInfoEquals(authService.authenticationInfo.user, anonymous)).to.be.true;
            expect(areUserInfoEquals(authService.authenticationInfo.unsafeUser, loginInfo)).to.be.true;
            expect(areUserInfoEquals(authService.authenticationInfo.actualUser, anonymous)).to.be.true;
            expect(areUserInfoEquals(authService.authenticationInfo.unsafeActualUser, loginInfo)).to.be.true;
            expect(authService.authenticationInfo.level).to.be.equal(AuthLevel.Unsafe);
            expect(authService.token).to.be.equal('CfDJ8CS62…pLB10X');
            expect(authService.refreshable).to.be.equal(false);
            expect(authService.currentError.error).to.be.equal(null);

            serverResponse = emptyResponse;
            await authService.logout(true);

            expect(areUserInfoEquals(authService.authenticationInfo.user, anonymous)).to.be.true;
            expect(areUserInfoEquals(authService.authenticationInfo.unsafeUser, anonymous)).to.be.true;
            expect(areUserInfoEquals(authService.authenticationInfo.actualUser, anonymous)).to.be.true;
            expect(areUserInfoEquals(authService.authenticationInfo.unsafeActualUser, anonymous)).to.be.true;
            expect(authService.authenticationInfo.level).to.be.equal(AuthLevel.None);
            expect(authService.token).to.be.equal('');
            expect(authService.refreshable).to.be.equal(false);
            expect(authService.currentError.error).to.be.equal(null);
        });

        it('should parse unsafeDirectLogin response.', async function () {
            const loginInfo: IUserInfo = {
                userId: 2,
                userName: 'Alice',
                schemes: [{ name: 'Basic', lastUsed: schemeLastUsed }]
            }

            serverResponse = new ResponseBuilder()
                .withUser({ id: 2, name: 'Alice', schemes: [{ name: 'Basic', lastUsed: schemeLastUsed }] })
                .withExpires(exp)
                .withToken('CfDJ8CS62…pLB10X')
                .withRefreshable(false)
                .build();
            await authService.unsafeDirectLogin('', {});

            expect(areUserInfoEquals(authService.authenticationInfo.user, loginInfo)).to.be.true;
            expect(areUserInfoEquals(authService.authenticationInfo.unsafeUser, loginInfo)).to.be.true;
            expect(areUserInfoEquals(authService.authenticationInfo.actualUser, loginInfo)).to.be.true;
            expect(areUserInfoEquals(authService.authenticationInfo.unsafeActualUser, loginInfo)).to.be.true;
            expect(authService.authenticationInfo.level).to.be.equal(AuthLevel.Normal);
            expect(authService.token).to.be.equal('CfDJ8CS62…pLB10X');
            expect(authService.refreshable).to.be.equal(false);
            expect(authService.currentError.error).to.equal(null);

            serverResponse = new ResponseBuilder()
                .withError({ errorId: 'System.ArgumentException', errorText: 'Invalid payload.' })
                .build();
            await authService.unsafeDirectLogin('', {});

            expect(areUserInfoEquals(authService.authenticationInfo.user, anonymous)).to.be.true;
            expect(areUserInfoEquals(authService.authenticationInfo.unsafeUser, anonymous)).to.be.true;
            expect(areUserInfoEquals(authService.authenticationInfo.actualUser, anonymous)).to.be.true;
            expect(areUserInfoEquals(authService.authenticationInfo.unsafeActualUser, anonymous)).to.be.true;
            expect(authService.authenticationInfo.level).to.be.equal(AuthLevel.None);
            expect(authService.token).to.be.equal('');
            expect(authService.refreshable).to.be.equal(false);
            expect(authService.currentError).to.deep.equal(new WebFrontAuthError({
                errorId: 'System.ArgumentException',
                errorReason: 'Invalid payload.'
            }));
        });

        it('should parse impersonate response.', async function () {
            const impersonatedLoginInfo: IUserInfo = {
                userId: 3,
                userName: 'Bob',
                schemes: []
            }

            const impersonatorLoginInfo: IUserInfo = {
                userId: 2,
                userName: 'Alice',
                schemes: [{ name: 'Basic', lastUsed: schemeLastUsed }]
            }

            serverResponse = new ResponseBuilder()
                .withUser({ id: 3, name: 'Bob', schemes: [] })
                .withActualUser({ id: 2, name: 'Alice', schemes: [{ name: 'Basic', lastUsed: schemeLastUsed }] })
                .withExpires(exp)
                .withToken('CfDJ…s4POjOs')
                .withRefreshable(false)
                .build();
            await authService.impersonate('');

            expect(areUserInfoEquals(authService.authenticationInfo.user, impersonatedLoginInfo)).to.be.true;
            expect(areUserInfoEquals(authService.authenticationInfo.unsafeUser, impersonatedLoginInfo)).to.be.true;
            expect(areUserInfoEquals(authService.authenticationInfo.actualUser, impersonatorLoginInfo)).to.be.true;
            expect(areUserInfoEquals(authService.authenticationInfo.unsafeActualUser, impersonatorLoginInfo)).to.be.true;
            expect(authService.authenticationInfo.level).to.be.equal(AuthLevel.Normal);
            expect(authService.token).to.be.equal('CfDJ…s4POjOs');
            expect(authService.refreshable).to.be.equal(false);
            expect(authService.currentError.error).to.equal(null);
        });

    });

    context('when authentication info changes', function () {

        it('should call OnChange().', async function () {
            let authenticationInfo: IAuthenticationInfo;
            let token: string;

            const updateAuthenticationInfo = () => authenticationInfo = authService.authenticationInfo;
            const updateToken = () => token = authService.token;
            authService.addOnChange(updateAuthenticationInfo);
            authService.addOnChange(updateToken);

            serverResponse = new ResponseBuilder()
                .withUser({ id: 2, name: 'Alice', schemes: [{ name: 'Basic', lastUsed: schemeLastUsed }] })
                .withExpires(exp)
                .withToken('CfDJ8CS62…pLB10X')
                .withRefreshable(true)
                .build();
            await authService.basicLogin('', '');

            expect(areUserInfoEquals(authenticationInfo.user, anonymous)).to.be.false;
            expect(token).to.not.be.equal('');

            serverResponse = emptyResponse;
            await authService.logout(true);

            expect(areUserInfoEquals(authenticationInfo.user, anonymous)).to.be.true;
            expect(token).to.be.equal('');

            authService.removeOnChange(updateAuthenticationInfo);

            serverResponse = new ResponseBuilder()
                .withUser({ id: 2, name: 'Alice', schemes: [{ name: 'Basic', lastUsed: schemeLastUsed }] })
                .withExpires(exp)
                .withToken('CfDJ8CS62…pLB10X')
                .withRefreshable(true)
                .build();
            await authService.basicLogin('', '');

            expect(areUserInfoEquals(authenticationInfo.user, anonymous)).to.be.true;
            expect(token).to.not.be.equal('');
        });

        it('should contains the source as an Event parameter.', async function () {
            const assertEventSource = (source: AuthService) => expect(source).to.deep.equal(authService);
            authService.addOnChange(assertEventSource);

            serverResponse = new ResponseBuilder()
                .withUser({ id: 2, name: 'Alice', schemes: [{ name: 'Basic', lastUsed: schemeLastUsed }] })
                .withExpires(exp)
                .withToken('CfDJ8CS62…pLB10X')
                .withRefreshable(true)
                .build();
            await authService.basicLogin('', '');
        });

        /**
         * NOTE
         * Do not use async here. Otherwise an "method is overspecified" error will be throw.
         * This error is thrown whenever a function returns a promise and uses the done callback.
         * Since this test relies on events' callback, we call done() after the last expectation.
         */
        it('should start expires and critical expires respective timers', function (done) {

            const expires = new Date();
            expires.setMilliseconds(expires.getMilliseconds() + 100);
            const criticalExpires = new Date();
            criticalExpires.setMilliseconds(expires.getMilliseconds() + 100);

            const assertCriticalExpiresDemoted = (source: AuthService) => {
                expect(source.authenticationInfo.level === AuthLevel.Normal);
                source.removeOnChange(assertCriticalExpiresDemoted);
                source.addOnChange(assertExpiresDemoted);
            }

            const assertExpiresDemoted = (source: AuthService) => {
                expect(source.authenticationInfo.level === AuthLevel.Unsafe);
                source.removeOnChange(assertExpiresDemoted);
                done();
            }

            serverResponse = new ResponseBuilder()
                .withUser({ id: 2, name: 'Alice', schemes: [{ name: 'Basic', lastUsed: schemeLastUsed }] })
                .withExpires(expires)
                .withCriticalExpires(criticalExpires)
                .withToken('Cf0DEq...Fd10xRD')
                .withRefreshable(false)
                .build();

            authService.basicLogin('', '').then(_ => {
                expect(authService.authenticationInfo.level).to.be.equal(AuthLevel.Critical);
                authService.addOnChange(assertCriticalExpiresDemoted);
            });
        });
    });

});
