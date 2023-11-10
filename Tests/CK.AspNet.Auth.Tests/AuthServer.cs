using CK.AspNet.Tester;
using CK.Auth;
using CK.Core;
using FluentAssertions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Newtonsoft.Json.Linq;
using System;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web;
using static CK.Testing.MonitorTestHelper;

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

        public AuthServer( Action<WebFrontAuthOptions>? options = null,
                           Action<IServiceCollection>? configureServices = null,
                           Action<IApplicationBuilder>? configureApplication = null )
        {
            // This enable the RootLogPath to be initialized before the GrandOutput.
            TestHelper.Monitor.Info( "AuthServer initialisation." );
            var b = Tester.WebHostBuilderFactory.Create( null, null,
                services =>
                {
                    services.AddSingleton<AuthenticationInfoTokenService>();
                    services.AddSingleton<IAuthenticationTypeSystem, StdAuthenticationTypeSystem>();
                    services.AddAuthentication( WebFrontAuthOptions.OnlyAuthenticationScheme ).AddWebFrontAuth( options );
                    services.AddSingleton<FakeWebFrontLoginService>();
                    services.AddSingleton<IWebFrontAuthLoginService>( sp => sp.GetRequiredService<FakeWebFrontLoginService>() );
                    configureServices?.Invoke( services );
                },
                app =>
                {
                    app.UseGuardRequestMonitor();
                    _typeSystem = (IAuthenticationTypeSystem)app.ApplicationServices.GetService( typeof( IAuthenticationTypeSystem ) );
                    app.UseAuthentication();
                    Options = app.ApplicationServices.GetRequiredService<IOptionsMonitor<WebFrontAuthOptions>>();
                    app.Use( prev =>
                    {
                        return async ctx =>
                        {
                            if( ctx.Request.Path.StartsWithSegments( "/echo", out var remaining ) )
                            {
                                var echo = remaining.ToString();
                                if( ctx.Request.QueryString.HasValue ) echo += " => " + ctx.Request.QueryString;

                                if( remaining.StartsWithSegments( "/error", out var errorCode ) && Int32.TryParse( errorCode, out var error ) )
                                {
                                    ctx.Response.StatusCode = error;
                                    echo += $" (StatusCode set to '{error}')";
                                }
                                if( ctx.Request.Query.ContainsKey( "userName" ) )
                                {
                                    var authInfo = CKAspNetAuthHttpContextExtensions.GetAuthenticationInfo( ctx );
                                    echo += $" (UserName: '{authInfo.User.UserName}')";
                                }
                                await ctx.Response.Body.WriteAsync( System.Text.Encoding.UTF8.GetBytes( echo ) );
                            }
                            else if( ctx.Request.Path.StartsWithSegments( "/CallChallengeAsync", out _ ) )
                            {
                                await Microsoft.AspNetCore.Authentication.AuthenticationHttpContextExtensions.ChallengeAsync( ctx );
                            }
                            else if( ctx.Request.Path.StartsWithSegments( "/ComingFromCris/LogoutCommand", out _ ) )
                            {
                                var s = app.ApplicationServices.GetRequiredService<WebFrontAuthService>();
                                await s.LogoutCommandAsync( new ActivityMonitor(), ctx );
                                ctx.Response.StatusCode = 200;
                            }
                            else if( ctx.Request.Path.StartsWithSegments( "/ComingFromCris/LoginCommand", out _ ) )
                            {
                                var s = app.ApplicationServices.GetRequiredService<WebFrontAuthService>();
                                var r = await s.BasicLoginCommandAsync( new ActivityMonitor(),
                                                                        ctx,
                                                                        ctx.Request.Query["userName"],
                                                                        "success",
                                                                        impersonateActualUser: ctx.Request.Query["impersonateActualUser"] == "True" );
                                ctx.Response.StatusCode = 200;
                                await ctx.Response.WriteAsync( r.Token );
                            }
                            else
                            {
                                await prev( ctx );
                            }
                        };
                    } );
                    configureApplication?.Invoke( app );
                }, builder => builder.UseScopedHttpContext()
            ).UseCKMonitoring();
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

        public async Task<RefreshResponse> LoginViaBasicLoginCommandAsync( string userName,
                                                                           bool impersonateActualUser = false )
        {
            using HttpResponseMessage getResponse = await Client.GetAsync( $"/ComingFromCris/LoginCommand?userName={userName}&impersonateActualUser={impersonateActualUser}" );
            var token = await getResponse.Content.ReadAsStringAsync();
            Client.Token = token;
            var r = await CallRefreshEndPointAsync();
            return r;
        }


        public Task<RefreshResponse> LoginAlbertViaBasicProviderAsync( bool useGenericWrapper = false, bool rememberMe = true, bool impersonateActualUser = false )
            => LoginViaBasicProviderAsync( "Albert", useGenericWrapper, rememberMe, impersonateActualUser );

        public async Task<RefreshResponse> LoginViaBasicProviderAsync( string userName,
                                                                       bool useGenericWrapper = false,
                                                                       bool rememberMe = true,
                                                                       bool impersonateActualUser = false,
                                                                       string? jsonUserData = null )
        {
            string uri;
            string body;
            if( useGenericWrapper )
            {
                uri = UnsafeDirectLoginUri;
                if( rememberMe )
                {
                    if( impersonateActualUser )
                    {
                        body = "{ \"Provider\":\"Basic\", \"RememberMe\":true, \"ImpersonateActualUser\":true, \"Payload\": {\"userName\":\""+userName+"\",\"password\":\"success\"}";
                    }
                    else
                    {
                        body = "{ \"Provider\":\"Basic\", \"RememberMe\":true, \"Payload\": {\"userName\":\"" + userName + "\",\"password\":\"success\"}";
                    }
                }
                else
                {
                    if( impersonateActualUser )
                    {
                        body = "{ \"Provider\":\"Basic\", \"ImpersonateActualUser\":true, \"Payload\": {\"userName\":\"" + userName + "\",\"password\":\"success\"}";
                    }
                    else
                    {
                        body = "{ \"Provider\":\"Basic\", \"Payload\": {\"userName\":\"" + userName + "\",\"password\":\"success\"}";
                    }
                }
            }
            else
            {
                uri = BasicLoginUri;
                if( rememberMe )
                {
                    if( impersonateActualUser )
                    {
                        body = "{\"userName\":\"" + userName + "\",\"password\":\"success\",\"rememberMe\":true, \"impersonateActualUser\":true";
                    }
                    else
                    {
                        body = "{\"userName\":\"" + userName + "\",\"password\":\"success\",\"rememberMe\":true";
                    }
                }
                else
                {
                    if( impersonateActualUser )
                    {
                        body = "{\"userName\":\"" + userName + "\",\"password\":\"success\",\"ImpersonateActualUser\":true";
                    }
                    else
                    {
                        body = "{\"userName\":\"" + userName + "\",\"password\":\"success\"";
                    }
                }
            }
            if( jsonUserData != null )
            {
                body += $@", ""userData"": {jsonUserData}";
            }
            body += "}";
            using HttpResponseMessage response = await Client.PostJSONAsync( uri, body );
            return await HandleLoginResponseAsync( response, userName, rememberMe );
        }

        async Task<RefreshResponse> HandleLoginResponseAsync( HttpResponseMessage response, string userName, bool rememberMe )
        {
            response.EnsureSuccessStatusCode();

            var c = RefreshResponse.Parse( TypeSystem, await response.Content.ReadAsStringAsync() );
            c.Info.Level.Should().Be( AuthLevel.Normal );
            c.Info.ActualUser.UserName.Should().Be( userName );

            var cookieName = Options.Get( WebFrontAuthOptions.OnlyAuthenticationScheme ).AuthCookieName;
            var ltCookieName = cookieName + "LT";
            switch( Options.Get( WebFrontAuthOptions.OnlyAuthenticationScheme ).CookieMode )
            {
                case AuthenticationCookieMode.WebFrontPath:
                    {
                        Client.Cookies.GetCookies( Server.BaseAddress ).Should().BeEmpty();
                        var all = Client.Cookies.GetCookies( new Uri( Server.BaseAddress, "/.webfront/c/" ) );
                        all.Should().HaveCount( 2 );
                        CookieIsNotTheSameAsToken( all, cookieName, c );
                        CheckLongTermCookie( rememberMe, all, ltCookieName );
                        break;
                    }
                case AuthenticationCookieMode.RootPath:
                    {
                        var all = Client.Cookies.GetCookies( Server.BaseAddress );
                        all.Should().HaveCount( 2 );
                        CookieIsNotTheSameAsToken( all, cookieName, c );
                        CheckLongTermCookie( rememberMe, all, ltCookieName );
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

            c.RememberMe.Should().Be( rememberMe );
            return c;

            static void CheckLongTermCookie( bool rememberMe, System.Net.CookieCollection all, string cookieName )
            {
                var cookie = all.Single( c => c.Name == cookieName ).Value;
                cookie = HttpUtility.UrlDecode( cookie );
                var longTerm = JObject.Parse( cookie );
                ((string)longTerm[StdAuthenticationTypeSystem.DeviceIdKeyType]).Should().NotBeEmpty( "There is always a non empty 'device' member." );
                longTerm.ContainsKey( StdAuthenticationTypeSystem.UserIdKeyType ).Should().Be( rememberMe, "The user is here only when remember is true." );
            }

            static void CookieIsNotTheSameAsToken( System.Net.CookieCollection all, string cookieName, RefreshResponse r )
            {
                var cookie = all.Single( c => c.Name == cookieName ).Value;
                cookie = HttpUtility.UrlDecode( cookie );
                cookie.Should().NotBe( r.Token );
            }
        }

        public (string? AuthCookie, JObject? LTCookie, string? LTDeviceId, string? LTUserId, string? LTUserName) ReadClientCookies()
        {
            var mode = Options.Get( WebFrontAuthOptions.OnlyAuthenticationScheme ).CookieMode;
            System.Net.CookieCollection? all = null;
            switch( mode )
            {
                case AuthenticationCookieMode.WebFrontPath:
                    {
                        all = Client.Cookies.GetCookies( new Uri( Server.BaseAddress, "/.webfront/c/" ) );
                        break;
                    }
                case AuthenticationCookieMode.RootPath:
                    {
                        all = Client.Cookies.GetCookies( Server.BaseAddress );
                        break;
                    }
                default: Debug.Assert( mode == AuthenticationCookieMode.None );
                         break;
            }

            string? authCookie = all?.SingleOrDefault( c => c.Name == Options.Get( WebFrontAuthOptions.OnlyAuthenticationScheme ).AuthCookieName )?.Value;
            JObject ltCookie = null;
            string? ltDeviceId = null;
            string? ltUserId = null;
            string? ltUserName = null;

            var ltCookieStr = all?.SingleOrDefault( c => c.Name == Options.Get( WebFrontAuthOptions.OnlyAuthenticationScheme ).AuthCookieName + "LT" )?.Value;
            if( ltCookieStr != null )
            {
                ltCookieStr = HttpUtility.UrlDecode( ltCookieStr );
                ltCookie = JObject.Parse( ltCookieStr );
                ltDeviceId = (string)ltCookie[StdAuthenticationTypeSystem.DeviceIdKeyType];
                ltUserId = (string)ltCookie[StdAuthenticationTypeSystem.UserIdKeyType];
                ltUserName = (string)ltCookie[StdAuthenticationTypeSystem.UserNameKeyType];
            }
            return (authCookie, ltCookie, ltDeviceId, ltUserId, ltUserName );
        }

        public async Task<RefreshResponse> CallRefreshEndPointAsync( bool withVersion = false, bool withSchemes = false )
        {
            var url = RefreshUri;
            if( withVersion && withSchemes )
            {
                url += "?version&schemes";
            }
            else if( withVersion ) url += "?version";
            else if( withSchemes ) url += "?schemes";

            HttpResponseMessage tokenRefresh = await Client.GetAsync( url );
            tokenRefresh.EnsureSuccessStatusCode();
            return RefreshResponse.Parse( TypeSystem, await tokenRefresh.Content.ReadAsStringAsync() );
        }

        public void Dispose() => Server?.Dispose();

    }

}
