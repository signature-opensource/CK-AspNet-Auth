using CK.AspNet.Tester;
using CK.Auth;
using FluentAssertions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Newtonsoft.Json.Linq;
using System;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using System.Web;

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
            Action<WebFrontAuthOptions>? options = null,
            Action<IServiceCollection>? configureServices = null,
            Action<IApplicationBuilder>? configureApplication = null )
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
                    app.UseGuardRequestMonitor();
                    _typeSystem = (IAuthenticationTypeSystem)app.ApplicationServices.GetService( typeof( IAuthenticationTypeSystem ) );
                    app.UseAuthentication();
                    Options = app.ApplicationServices.GetRequiredService<IOptionsMonitor<WebFrontAuthOptions>>();
                    configureApplication?.Invoke( app );
                }, builder => builder.UseScopedHttpContext()
            ).UseMonitoring();
            var host = b.Build();
            host.Start();
            Client = new TestServerClient( host );
            Server = Client.Server;
            Debug.Assert( _typeSystem != null );
            Debug.Assert( Options != null );
        }

        public IAuthenticationTypeSystem TypeSystem => _typeSystem;

        public IOptionsMonitor<WebFrontAuthOptions> Options { get; private set; }

        public TestServer Server { get; }

        public TestServerClient Client { get; }


        public async Task<RefreshResponse> LoginAlbertViaBasicProvider( bool useGenericWrapper = false, bool rememberMe = true )
        {
            string uri;
            string body;
            if( useGenericWrapper )
            {
                uri = UnsafeDirectLoginUri;
                if( rememberMe )
                {
                    body = "{ \"Provider\":\"Basic\", \"RememberMe\":true, \"Payload\": {\"userName\":\"Albert\",\"password\":\"success\"} }";
                }
                else
                {
                    body = "{ \"Provider\":\"Basic\", \"Payload\": {\"userName\":\"Albert\",\"password\":\"success\"} }";
                }
            }
            else
            {
                uri = BasicLoginUri;
                if( rememberMe )
                {
                    body = "{\"userName\":\"Albert\",\"password\":\"success\",\"rememberMe\":true}";
                }
                else
                {
                    body = "{\"userName\":\"Albert\",\"password\":\"success\"}";
                }
            }
            HttpResponseMessage response = await Client.PostJSON( uri, body );
            response.EnsureSuccessStatusCode();
            switch( Options.Get( WebFrontAuthOptions.OnlyAuthenticationScheme ).CookieMode )
            {
                case AuthenticationCookieMode.WebFrontPath:
                    {
                        Client.Cookies.GetCookies( Server.BaseAddress ).Should().BeEmpty();
                        var all = Client.Cookies.GetCookies( new Uri( Server.BaseAddress, "/.webfront/c/" ) );
                        all.Should().HaveCount( 2 );
                        CheckLongTermCookie( rememberMe, all );
                        break;
                    }
                case AuthenticationCookieMode.RootPath:
                    {
                        var all = Client.Cookies.GetCookies( Server.BaseAddress );
                        all.Should().HaveCount( 2 );
                        CheckLongTermCookie( rememberMe, all );
                        break;
                    }
                case AuthenticationCookieMode.None:
                    {
                        // RemeberMe returned by the server is always false when CookieMode is None.
                        rememberMe = false;
                        Client.Cookies.GetCookies( Server.BaseAddress ).Should().BeEmpty();
                        Client.Cookies.GetCookies( new Uri( Server.BaseAddress, "/.webfront/c/" ) ).Should().BeEmpty();
                        break;
                    }
            }
            var c = RefreshResponse.Parse( TypeSystem, response.Content.ReadAsStringAsync().Result );
            c.Info.Level.Should().Be( AuthLevel.Normal );
            c.Info.User.UserName.Should().Be( "Albert" );
            c.RememberMe.Should().Be( rememberMe );
            return c;

            static void CheckLongTermCookie( bool rememberMe, System.Net.CookieCollection all )
            {
                var cookie = all.Single( c => c.Name == WebFrontAuthService.UnsafeCookieName ).Value;
                cookie = HttpUtility.UrlDecode( cookie );
                var longTerm = JObject.Parse( cookie );
                ((string)longTerm[StdAuthenticationTypeSystem.DeviceIdKeyType]).Should().NotBeEmpty( "There is always a non empty 'device' member." );
                longTerm.ContainsKey( StdAuthenticationTypeSystem.UserIdKeyType ).Should().Be( rememberMe, "The user is here only when remember is true." );
            }
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
