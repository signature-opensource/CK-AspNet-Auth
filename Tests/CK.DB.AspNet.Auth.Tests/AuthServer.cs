using CK.AspNet.Auth;
using CK.AspNet.Tester;
using CK.Auth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using System;
using static CK.Testing.DBSetupTestHelper;

namespace CK.DB.AspNet.Auth.Tests
{
    class AuthServer : IDisposable
    {
        IAuthenticationTypeSystem _typeSystem;
        WebFrontAuthService _authService;

        public AuthServer(
            Action<WebFrontAuthOptions> options = null,
            Action<IServiceCollection> configureServices = null,
            Action<IApplicationBuilder> configureApplication = null )
        {
            var b = CK.AspNet.Tester.WebHostBuilderFactory.Create( null, null,
                services =>
                {
                    services.AddAuthentication().AddWebFrontAuth( options );
                    services.AddCKDatabase( TestHelper.StObjMap );
                    configureServices?.Invoke( services );
                },
                app =>
                {
                    app.UseRequestMonitor();
                    _typeSystem = (IAuthenticationTypeSystem)app.ApplicationServices.GetService( typeof( IAuthenticationTypeSystem ) );
                    _authService = (WebFrontAuthService)app.ApplicationServices.GetService( typeof( WebFrontAuthService ) );
                    app.UseAuthentication();
                    configureApplication?.Invoke( app );
                } );
            b.UseMonitoring();
            Server = new TestServer( b );
            Client = new TestServerClient( Server );
        }

        public WebFrontAuthService AuthService => _authService;

        public IAuthenticationTypeSystem TypeSystem => _typeSystem;

        public TestServer Server { get; }

        public TestServerClient Client { get; }

        public void Dispose()
        {
            Server?.Dispose();
        }
    }

}
