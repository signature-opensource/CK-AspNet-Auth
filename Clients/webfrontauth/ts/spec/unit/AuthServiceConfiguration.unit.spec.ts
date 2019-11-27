import { expect } from 'chai';

import { IAuthServiceConfiguration } from '../..';
import { AuthServiceConfiguration } from '../../src/index.private';

describe('AuthServiceConfiguration', function () {

    context('when parsing identityEndPoint', function () {

        it('should build the url.', function () {
            let configuration: IAuthServiceConfiguration = { identityEndPoint: { hostname: 'host', disableSsl: false, port: 1337 } };
            let authConfiguration = new AuthServiceConfiguration(configuration);
            expect(authConfiguration.webFrontAuthEndPoint).to.be.equal('https://host:1337/');

            configuration = { identityEndPoint: {} };
            authConfiguration = new AuthServiceConfiguration(configuration);
            expect(authConfiguration.webFrontAuthEndPoint).to.be.equal('/');
        });

        it('should parse disableSsl accordingly.', function () {
            let configuration: IAuthServiceConfiguration = { identityEndPoint: { hostname: 'host', disableSsl: true, port: 3712 } };
            let authConfiguration = new AuthServiceConfiguration(configuration);
            expect(authConfiguration.webFrontAuthEndPoint).to.satisfy((s: string) => s.startsWith('http'));

            configuration = { identityEndPoint: { hostname: 'hostname', disableSsl: false, port: 3712 } };
            authConfiguration = new AuthServiceConfiguration(configuration);
            expect(authConfiguration.webFrontAuthEndPoint).to.satisfy((s: string) => s.startsWith('https'));
        });

        it('should not expose default port.', function () {
            let configuration: IAuthServiceConfiguration = { identityEndPoint: { hostname: 'host', disableSsl: true, port: 80 } };
            let authConfiguration = new AuthServiceConfiguration(configuration);
            expect(authConfiguration.webFrontAuthEndPoint).to.be.equal('http://host/')

            configuration = { identityEndPoint: { hostname: 'host', disableSsl: false, port: 443 } };
            authConfiguration = new AuthServiceConfiguration(configuration);
            expect(authConfiguration.webFrontAuthEndPoint).to.be.equal('https://host/')
        });

    });

});
