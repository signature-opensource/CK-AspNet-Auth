using CK.AspNet.Tester;
using CK.Auth;
using FluentAssertions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Net.Http;

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
        WebFrontAuthService _authService;

        public AuthServer(
            WebFrontAuthMiddlewareOptions options,
            Action<IServiceCollection> configureServices = null,
            Action<IApplicationBuilder> configureApplication = null )
        {
            Options = options;
            var b = WebHostBuilderFactory.Create( null, null,
                services =>
                {
                    services.AddAuthentication();
                    services.AddSingleton<IAuthenticationTypeSystem, StdAuthenticationTypeSystem>();
                    services.AddSingleton<IWebFrontAuthLoginService, FakeWebFrontLoginService>();
                    services.AddSingleton<WebFrontAuthService>();
                    configureServices?.Invoke( services );
                },
                app =>
                {
                    app.UseRequestMonitor();
                    _typeSystem = (IAuthenticationTypeSystem)app.ApplicationServices.GetService( typeof( IAuthenticationTypeSystem ) );
                    _authService = (WebFrontAuthService)app.ApplicationServices.GetService( typeof( WebFrontAuthService ) );
                    app.UseWebFrontAuth( options );
                    configureApplication?.Invoke( app );
                } );
            Server = new TestServer( b );
            Client = new TestServerClient( Server );
        }

        public IAuthenticationTypeSystem TypeSystem => _typeSystem;

        public WebFrontAuthMiddlewareOptions Options { get; }

        public TestServer Server { get; }

        public TestServerClient Client { get; }


        public RefreshResponse LoginAlbertViaBasicProvider( bool useGenericWrapper = false )
        {
            HttpResponseMessage response = useGenericWrapper
                                            ? Client.PostJSON( UnsafeDirectLoginUri, "{ \"Provider\":\"Basic\", \"Payload\": {\"userName\":\"Albert\",\"password\":\"success\"} }" )
                                            : Client.PostJSON( BasicLoginUri, "{\"userName\":\"Albert\",\"password\":\"success\"}" );
            response.EnsureSuccessStatusCode();
            switch( Options.CookieMode )
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

        public RefreshResponse CallRefreshEndPoint()
        {
            HttpResponseMessage tokenRefresh = Client.Get( RefreshUri );
            tokenRefresh.EnsureSuccessStatusCode();
            return RefreshResponse.Parse( TypeSystem, tokenRefresh.Content.ReadAsStringAsync().Result );
        }


        public void Dispose() => Server?.Dispose();

    }

}
