using CK.AspNet.Auth;
using CK.AspNet.Tester;
using CK.Auth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using static CK.Testing.DBSetupTestHelper;

namespace CK.DB.AspNet.Auth.Tests
{
    class AuthServer : IDisposable
    {
        IAuthenticationTypeSystem _typeSystem;

        public AuthServer(
            Action<IServiceCollection> configureServices = null,
            Action<IApplicationBuilder> configureApplication = null )
        {
            var b = CK.AspNet.Tester.WebHostBuilderFactory.Create( null, null,
                services =>
                {
                    services.AddAuthentication().AddWebFrontAuth();
                    services.AddCKDatabase( TestHelper.Monitor, TestHelper.StObjMap );
                    configureServices?.Invoke( services );
                },
                app =>
                {
                    app.UseGuardRequestMonitor();
                    _typeSystem = (IAuthenticationTypeSystem)app.ApplicationServices.GetService( typeof( IAuthenticationTypeSystem ) );
                    app.UseAuthentication();
                    configureApplication?.Invoke( app );
                },
                builder => builder.UseScopedHttpContext() )
                .UseMonitoring();
            var host = b.Build();
            host.Start();
            Client = new TestServerClient( host );
            Server = Client.Server;
        }

        public IAuthenticationTypeSystem TypeSystem => _typeSystem;

        public TestServer Server { get; }

        public TestServerClient Client { get; }

        public void Dispose()
        {
            Server?.Dispose();
        }
    }

}
