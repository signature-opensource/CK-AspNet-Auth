import { expect } from 'chai';
import axios, { AxiosRequestConfig, AxiosResponse, AxiosError } from 'axios';

import {
    AuthService,
    IAuthenticationInfo,
    AuthLevel,
    IUserInfo,
    IError,
    IAuthServiceConfiguration
} from '../../';
import { AuthServiceConfiguration } from '../../src/index.private';
import { areUserInfoEquals } from '../helpers/test-helpers';
import { responseJson } from '../helpers/sample-responses';

describe('AuthService', function() {
    enum EScenario {
        Normal = 'Normal',
        Unsafe = 'Unsafe',
        Failure = 'Failure',
        Error = 'Error',
        None = 'None'
    }
    let currentScenario: EScenario = EScenario.Normal;

    let authService: AuthService;

    const anonymous: IUserInfo = {
        userId: 0,
        userName: '',
        schemes: []
    };

    const noError: IError = {
        loginFailureCode: null,
        loginFailureReason: null,
        errorId: null,
        errorReason: null
    }

    let requestInterceptorId: number;
    let responseInterceptorId: number;
    
    before(function() {
        authService = new AuthService( { identityEndPoint: {} }, axios );

        axios.defaults.timeout = 0.1;
        requestInterceptorId = axios.interceptors.request.use((config: AxiosRequestConfig) => {
            config.url = `unitTest+${config.url}`;
            return config;
        });
        responseInterceptorId = axios.interceptors.response.use((response: AxiosResponse) => {
            return response; // never occurs
        }, (error: AxiosError) => {
            let currentRequest: string = error.config.url.slice(22);
            currentRequest += currentScenario !== EScenario.Normal ? currentScenario : '';
            const targetData = responseJson[currentRequest];
            return Promise.resolve({
                data: targetData,
                status: 200,
                statusText: 'Ok',
                headers: {},
                config: error.config
            });
        });
    });

    beforeEach(async function() {
        currentScenario = EScenario.Normal;
        await authService.logout();
    });

    after(function() {
        axios.interceptors.request.eject(requestInterceptorId);
        axios.interceptors.response.eject(responseInterceptorId);
        axios.defaults.timeout = 1000;
    });

    it('should parse configuration object correctly.', function() {
        let configuration: IAuthServiceConfiguration = { identityEndPoint: { hostname: 'host', disableSsl: false, port: 12345 } };

        let authConfiguration: AuthServiceConfiguration = new AuthServiceConfiguration(configuration);
        expect(authConfiguration.webFrontAuthEndPoint).to.be.equal('https://host:12345/');

        configuration = { identityEndPoint: {} };
        authConfiguration = new AuthServiceConfiguration(configuration);
        expect(authConfiguration.webFrontAuthEndPoint).to.be.equal('/');
    });

    it('should parse basicLogin response correctly.', async function() {
        const loginInfo: IUserInfo = {
            userId: 2,
            userName: 'Albert',
            schemes: [ { name: 'Basic', lastUsed: new Date('3000-03-26T14:50:48.5767287Z') } ]
        }

        currentScenario = EScenario.Failure;
        await authService.basicLogin('', '');

        let currentModel = authService.authenticationInfo;
        {
            expect(areUserInfoEquals(currentModel.user, anonymous)).to.be.true;
            expect(areUserInfoEquals(currentModel.unsafeUser, anonymous)).to.be.true;
            expect(areUserInfoEquals(currentModel.actualUser, anonymous)).to.be.true;
            expect(areUserInfoEquals(currentModel.unsafeActualUser, anonymous)).to.be.true;
            expect(currentModel.level).to.be.equal(AuthLevel.None);
            expect(authService.token).to.be.equal('');
            expect(authService.refreshable).to.be.equal(false);
            expect(authService.errorCollector).to.deep.equal( {
                ...noError,
                loginFailureCode: 4,
                loginFailureReason: 'Invalid credentials.'
            } );
        }
        
        currentScenario = EScenario.Unsafe;
        await authService.basicLogin('', '');

        currentModel = authService.authenticationInfo;
        {
            expect(areUserInfoEquals(currentModel.user, anonymous)).to.be.true;
            expect(areUserInfoEquals(currentModel.unsafeUser, loginInfo)).to.be.true;
            expect(areUserInfoEquals(currentModel.actualUser, anonymous)).to.be.true;
            expect(areUserInfoEquals(currentModel.unsafeActualUser, loginInfo)).to.be.true;
            expect(currentModel.level).to.be.equal(AuthLevel.Unsafe);
            expect(authService.token).to.be.equal('CfDJ8CS62…pLB10X');
            expect(authService.refreshable).to.be.equal(false);
            expect(authService.errorCollector).to.deep.equal(noError);
        }

        currentScenario = EScenario.Normal;
        await authService.basicLogin('', '');

        currentModel = authService.authenticationInfo;
        {
            expect(areUserInfoEquals(currentModel.user, loginInfo)).to.be.true;
            expect(areUserInfoEquals(currentModel.unsafeUser, loginInfo)).to.be.true;
            expect(areUserInfoEquals(currentModel.actualUser, loginInfo)).to.be.true;
            expect(areUserInfoEquals(currentModel.unsafeActualUser, loginInfo)).to.be.true;
            expect(currentModel.level).to.be.equal(AuthLevel.Normal);
            expect(authService.token).to.be.equal('CfDJ8CS62…pLB10X');
            expect(authService.refreshable).to.be.equal(false);
            expect(authService.errorCollector).to.deep.equal(noError);
        }
    });

    it('should parse refresh response correctly.', async function() {
        const loginInfo: IUserInfo = {
            userId: 2,
            userName: 'Albert',
            schemes: [ { name: 'Basic', lastUsed: new Date('3000-03-26T14:50:48.5767287Z') } ]
        }

        currentScenario = EScenario.Normal;
        await authService.basicLogin('', '');
        
        await authService.refresh();
        let currentModel = authService.authenticationInfo;
        { 
            expect(areUserInfoEquals(currentModel.user, loginInfo)).to.be.true;
            expect(areUserInfoEquals(currentModel.unsafeUser, loginInfo)).to.be.true;
            expect(areUserInfoEquals(currentModel.actualUser, loginInfo)).to.be.true;
            expect(areUserInfoEquals(currentModel.unsafeActualUser, loginInfo)).to.be.true;
            expect(currentModel.level).to.be.equal(AuthLevel.Normal);
            expect(authService.token).to.be.equal('CfDJ8CS62…pLB10X');
            expect(authService.refreshable).to.be.equal(false);
            expect(authService.errorCollector).to.deep.equal(noError);
            expect(authService.version).to.be.equal('v0.0.0-alpha');
        }

        currentScenario = EScenario.Unsafe;
        await authService.refresh();
        currentModel = authService.authenticationInfo;
        {
            expect(areUserInfoEquals(currentModel.user, anonymous)).to.be.true;
            expect(areUserInfoEquals(currentModel.unsafeUser, loginInfo)).to.be.true;
            expect(areUserInfoEquals(currentModel.actualUser, anonymous)).to.be.true;
            expect(areUserInfoEquals(currentModel.unsafeActualUser, loginInfo)).to.be.true;
            expect(currentModel.level).to.be.equal(AuthLevel.Unsafe);
            expect(authService.token).to.be.equal('CfDJ8CS62…pLB10X');
            expect(authService.refreshable).to.be.equal(false);
            expect(authService.errorCollector).to.deep.equal(noError);
        }

        currentScenario = EScenario.Failure;
        await authService.refresh();
        currentModel = authService.authenticationInfo;
        {
            expect(areUserInfoEquals(currentModel.user, anonymous)).to.be.true;
            expect(areUserInfoEquals(currentModel.unsafeUser, anonymous)).to.be.true;
            expect(areUserInfoEquals(currentModel.actualUser, anonymous)).to.be.true;
            expect(areUserInfoEquals(currentModel.unsafeActualUser, anonymous)).to.be.true;
            expect(currentModel.level).to.be.equal(AuthLevel.None);
            expect(authService.token).to.be.equal('');
            expect(authService.refreshable).to.be.equal(false);
            expect(authService.errorCollector).to.deep.equal( {
                ...noError,
                loginFailureCode: 4,
                loginFailureReason: 'Invalid credentials.'
            } );
        }
    });

    it('should parse logout response correctly.', async function() {
        const loginInfo: IUserInfo = {
            userId: 2,
            userName: 'Albert',
            schemes: [ { name: 'Basic', lastUsed: new Date('3000-03-26T14:50:48.5767287Z') } ]
        }

        currentScenario = EScenario.Normal;
        await authService.basicLogin('', '');

        let currentModel = authService.authenticationInfo;
        {
            expect(areUserInfoEquals(currentModel.user, loginInfo)).to.be.true;
            expect(areUserInfoEquals(currentModel.unsafeUser, loginInfo)).to.be.true;
            expect(areUserInfoEquals(currentModel.actualUser, loginInfo)).to.be.true;
            expect(areUserInfoEquals(currentModel.unsafeActualUser, loginInfo)).to.be.true;
            expect(currentModel.level).to.be.equal(AuthLevel.Normal);
            expect(authService.token).to.be.equal('CfDJ8CS62…pLB10X');
            expect(authService.refreshable).to.be.equal(false);
            expect(authService.errorCollector).to.deep.equal(noError);
        }

        currentScenario = EScenario.Unsafe;
        await authService.logout();
        currentModel = authService.authenticationInfo;
        {
            expect(areUserInfoEquals(currentModel.user, anonymous)).to.be.true;
            expect(areUserInfoEquals(currentModel.unsafeUser, loginInfo)).to.be.true;
            expect(areUserInfoEquals(currentModel.actualUser, anonymous)).to.be.true;
            expect(areUserInfoEquals(currentModel.unsafeActualUser, loginInfo)).to.be.true;
            expect(currentModel.level).to.be.equal(AuthLevel.Unsafe);
            expect(authService.token).to.be.equal('CfDJ8CS62…pLB10X');
            expect(authService.refreshable).to.be.equal(false);
        }
        
        currentScenario = EScenario.None;
        await authService.logout(true);
        currentModel = authService.authenticationInfo;
        {
            expect(areUserInfoEquals(currentModel.user, anonymous)).to.be.true;
            expect(areUserInfoEquals(currentModel.unsafeUser, anonymous)).to.be.true;
            expect(areUserInfoEquals(currentModel.actualUser, anonymous)).to.be.true;
            expect(areUserInfoEquals(currentModel.unsafeActualUser, anonymous)).to.be.true;
            expect(currentModel.level).to.be.equal(AuthLevel.None);
            expect(authService.token).to.be.equal('');
            expect(authService.refreshable).to.be.equal(false);
        }
    });

    it('should parse unsafeDirectLogin response correctly.', async function() {
        const loginInfo: IUserInfo = {
            userId: 2,
            userName: 'Albert',
            schemes: [ { name: 'Basic', lastUsed: new Date('3000-03-26T14:50:48.5767287Z') } ]
        }

        currentScenario = EScenario.Normal;
        await authService.unsafeDirectLogin('', {});
        
        let currentModel = authService.authenticationInfo;

        {
            expect(areUserInfoEquals(currentModel.user, loginInfo)).to.be.true;
            expect(areUserInfoEquals(currentModel.unsafeUser, loginInfo)).to.be.true;
            expect(areUserInfoEquals(currentModel.actualUser, loginInfo)).to.be.true;
            expect(areUserInfoEquals(currentModel.unsafeActualUser, loginInfo)).to.be.true;
            expect(currentModel.level).to.be.equal(AuthLevel.Normal);
            expect(authService.token).to.be.equal('CfDJ8CS62…pLB10X');
            expect(authService.refreshable).to.be.equal(false);
            expect(authService.errorCollector).to.deep.equal(noError);
        }

        currentScenario = EScenario.Error;
        await authService.unsafeDirectLogin('', {});
        currentModel = authService.authenticationInfo;
        {
            expect(areUserInfoEquals(currentModel.user, anonymous)).to.be.true;
            expect(areUserInfoEquals(currentModel.unsafeUser, anonymous)).to.be.true;
            expect(areUserInfoEquals(currentModel.actualUser, anonymous)).to.be.true;
            expect(areUserInfoEquals(currentModel.unsafeActualUser, anonymous)).to.be.true;
            expect(currentModel.level).to.be.equal(AuthLevel.None);
            expect(authService.token).to.be.equal('');
            expect(authService.refreshable).to.be.equal(false);
            expect(authService.errorCollector).to.deep.equal( { 
                ...noError, errorId: 'System.ArgumentException', errorReason: 'Invalid payload.'
            } );
        }
    });

    it('should parse impersonate response correctly.', async function() {
    const impersonatedLoginInfo: IUserInfo = {
        userId: 3,
        userName: 'Robert',
        schemes: []
    }

    const impersonatorLoginInfo: IUserInfo = {
        userId: 2,
        userName: 'Albert',
        schemes: [ { name: 'Basic', lastUsed: new Date('3000-07-28T16:33:26.2758228Z') } ]
    }

        currentScenario = EScenario.Normal;
        await authService.impersonate('');
        
        let currentModel = authService.authenticationInfo;
        {
            expect(areUserInfoEquals(currentModel.user, impersonatedLoginInfo)).to.be.true;
            expect(areUserInfoEquals(currentModel.unsafeUser, impersonatedLoginInfo)).to.be.true;
            expect(areUserInfoEquals(currentModel.actualUser, impersonatorLoginInfo)).to.be.true;
            expect(areUserInfoEquals(currentModel.unsafeActualUser, impersonatorLoginInfo)).to.be.true;
            expect(currentModel.level).to.be.equal(AuthLevel.Normal);
            expect(authService.token).to.be.equal('CfDJ…s4POjOs');
            expect(authService.refreshable).to.be.equal(false);
            expect(authService.errorCollector).to.deep.equal(noError);
        }
    });

    it('should call OnChange() correctly.', async function() {
        let authenticationInfo: IAuthenticationInfo;
        let token: string;
        
        const updateAuthenticationInfo = () => authenticationInfo = authService.authenticationInfo;
        const updateToken = () => token = authService.token;
        authService.addOnChange(updateAuthenticationInfo); 
        authService.addOnChange(updateToken); 

        currentScenario = EScenario.Normal;
        await authService.basicLogin('' , '');
        {
            expect(areUserInfoEquals(authenticationInfo.user, anonymous)).to.be.false;
            expect(token).to.not.be.equal('');
        }

        currentScenario = EScenario.None;
        await authService.logout(true);
        {
            expect(areUserInfoEquals(authenticationInfo.user, anonymous)).to.be.true;
            expect(token).to.be.equal('');
        }
        authService.removeOnChange(updateAuthenticationInfo);
        
        currentScenario = EScenario.Normal;
        await authService.basicLogin('' , '');
        {
            expect(areUserInfoEquals(authenticationInfo.user, anonymous)).to.be.true;
            expect(token).to.not.be.equal('');
        }
    });
});