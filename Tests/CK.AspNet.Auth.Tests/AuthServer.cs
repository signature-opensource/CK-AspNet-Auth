using CK.AspNet.Tester;
using CK.Auth;
using FluentAssertions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace CK.AspNet.Auth.Tests
{
    class AuthServer : IDisposable
    {
        public const string StartLoginUri = "/.webfront/c/startLogin";
        public const string BasicLoginUri = "/.webfront/c/basicLogin";
        public const string UnsafeDirectLoginUri = "/.webfront/c/unsafeDirectLogin";
        public const string RefreshUri = "/.webfront/c/refresh";
        public const string LogoutUri = "/.webfront/c/logout";
        public const string ImpersonateUri = "/.webfront/c/impersonate";
        public const string TokenExplainUri = "/.webfront/token";

        IAuthenticationTypeSystem _typeSystem;

        public AuthServer(
            Action<WebFrontAuthOptions> options = null,
            Action<IServiceCollection> configureServices = null,
            Action<IApplicationBuilder> configureApplication = null )
        {
            var b = Tester.WebHostBuilderFactory.Create( null, null,
                services =>
                {
                    services.AddSingleton<IAuthenticationTypeSystem, StdAuthenticationTypeSystem>();
                    services.AddAuthentication().AddWebFrontAuth( options );
                    services.AddSingleton<IWebFrontAuthLoginService, FakeWebFrontLoginService>();
                    configureServices?.Invoke( services );
                },
                app =>
                {
                    app.UseRequestMonitor();
                    _typeSystem = (IAuthenticationTypeSystem)app.ApplicationServices.GetService( typeof( IAuthenticationTypeSystem ) );
                    app.UseAuthentication();
                    Options = app.ApplicationServices.GetRequiredService<IOptionsMonitor<WebFrontAuthOptions>>();
                    configureApplication?.Invoke( app );
                } );
            b.UseMonitoring();
            Server = new TestServer( b );
            Client = new TestServerClient( Server );
        }

        public IAuthenticationTypeSystem TypeSystem => _typeSystem;

        public IOptionsMonitor<WebFrontAuthOptions> Options { get; private set; }

        public TestServer Server { get; }

        public TestServerClient Client { get; }


        public async Task<RefreshResponse> LoginAlbertViaBasicProvider( bool useGenericWrapper = false )
        {
            HttpResponseMessage response = useGenericWrapper
                                            ? await Client.PostJSON( UnsafeDirectLoginUri, "{ \"Provider\":\"Basic\", \"Payload\": {\"userName\":\"Albert\",\"password\":\"success\"} }" )
                                            : await Client.PostJSON( BasicLoginUri, "{\"userName\":\"Albert\",\"password\":\"success\"}" );
            response.EnsureSuccessStatusCode();
            switch( Options.Get( WebFrontAuthOptions.OnlyAuthenticationScheme ).CookieMode )
            {
                case AuthenticationCookieMode.WebFrontPath:
                    {
                        Client.Cookies.GetCookies( Server.BaseAddress ).Should().BeEmpty();
                        Client.Cookies.GetCookies( new Uri( Server.BaseAddress, "/.webfront/c/" ) ).Should().HaveCount( 2 );
                        break;
                    }
                case AuthenticationCookieMode.RootPath:
                    {
                        Client.Cookies.GetCookies( Server.BaseAddress ).Should().HaveCount( 2 );
                        break;
                    }
                case AuthenticationCookieMode.None:
                    {
                        Client.Cookies.GetCookies( Server.BaseAddress ).Should().BeEmpty();
                        Client.Cookies.GetCookies( new Uri( Server.BaseAddress, "/.webfront/c/" ) ).Should().BeEmpty();
                        break;
                    }
            }
            var c = RefreshResponse.Parse( TypeSystem, response.Content.ReadAsStringAsync().Result );
            c.Info.Level.Should().Be( AuthLevel.Normal );
            c.Info.User.UserName.Should().Be( "Albert" );
            return c;
        }

        public async Task<RefreshResponse> CallRefreshEndPoint()
        {
            HttpResponseMessage tokenRefresh = await Client.Get( RefreshUri );
            tokenRefresh.EnsureSuccessStatusCode();
            return RefreshResponse.Parse( TypeSystem, tokenRefresh.Content.ReadAsStringAsync().Result );
        }


        public void Dispose() => Server?.Dispose();

    }

}
