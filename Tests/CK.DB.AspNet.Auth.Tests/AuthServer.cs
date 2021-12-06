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
                    app.Use( prev =>
                    {
                        return async ctx =>
                        {
                            if( ctx.Request.Path.StartsWithSegments( "echo", out var remaining ) )
                            {
                                var echo = remaining.ToString();
                                if( ctx.Request.QueryString.HasValue ) echo += " => " + ctx.Request.QueryString;

                                if( remaining.StartsWithSegments( "error", out var errorCode ) && Int32.TryParse( errorCode, out var error ) )
                                {
                                    ctx.Response.StatusCode = error;
                                    echo += $" (StatusCode set to {error}.)";
                                }
                                await ctx.Response.Body.WriteAsync( System.Text.Encoding.UTF8.GetBytes( echo ) );
                            }
                            else
                            {
                                await prev( ctx );
                            }
                        };
                    } );
                    configureApplication?.Invoke( app );
                },
                builder => builder.UseScopedHttpContext() )
                .UseCKMonitoring();
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
