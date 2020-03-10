import { IAuthServiceConfiguration } from '../..';
import { AuthServiceConfiguration } from '../../src/index.private';

describe('AuthServiceConfiguration', function () {

    describe('when parsing identityEndPoint', function () {

        it('should build the url.', function () {
            let configuration: IAuthServiceConfiguration = { identityEndPoint: { hostname: 'host', disableSsl: false, port: 1337 } };
            let authConfiguration = new AuthServiceConfiguration(configuration);
            expect(authConfiguration.webFrontAuthEndPoint).toEqual('https://host:1337/');

            configuration = { identityEndPoint: {} };
            authConfiguration = new AuthServiceConfiguration(configuration);
            expect(authConfiguration.webFrontAuthEndPoint).toEqual('/');
        });

        it('should parse disableSsl accordingly.', function () {

            let configuration: IAuthServiceConfiguration = { identityEndPoint: { hostname: 'host', disableSsl: true, port: 3712 } };
            let authConfiguration = new AuthServiceConfiguration(configuration);
            let expectedStartWith = 'http';
            expect(authConfiguration.webFrontAuthEndPoint.slice(0, expectedStartWith.length)).toBe(expectedStartWith);

            configuration = { identityEndPoint: { hostname: 'hostname', disableSsl: false, port: 3712 } };
            authConfiguration = new AuthServiceConfiguration(configuration);
            expectedStartWith = 'https'
            expect(authConfiguration.webFrontAuthEndPoint.slice(0, expectedStartWith.length)).toBe(expectedStartWith);
        });

        it('should not expose default port.', function () {
            let configuration: IAuthServiceConfiguration = { identityEndPoint: { hostname: 'host', disableSsl: true, port: 80 } };
            let authConfiguration = new AuthServiceConfiguration(configuration);
            expect(authConfiguration.webFrontAuthEndPoint).toEqual('http://host/')

            configuration = { identityEndPoint: { hostname: 'host', disableSsl: false, port: 443 } };
            authConfiguration = new AuthServiceConfiguration(configuration);
            expect(authConfiguration.webFrontAuthEndPoint).toEqual('https://host/')
        });

    });

});
