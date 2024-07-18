using CK.AspNet.Auth;
using CK.Auth;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Newtonsoft.Json.Linq;
using System.Diagnostics;
using System.Linq;
using System;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web;
using CK.Core;
using FluentAssertions;

namespace CK.Testing
{
    public static class RunningAspNetAuthServerExtensions
    {
        /// <summary>
        /// The refresh authentication uri.
        /// </summary>
        public const string RefreshUri = "/.webfront/c/refresh";

        /// <summary>
        /// The unsafe direct login uri.
        /// </summary>
        public const string UnsafeDirectLoginUri = "/.webfront/c/unsafeDirectLogin";

        /// <summary>
        /// The basic login uri.
        /// </summary>
        public const string BasicLoginUri = "/.webfront/c/basicLogin";

        /// <summary>
        /// The impersonate uri.
        /// </summary>
        public const string ImpersonateUri = "/.webfront/c/impersonate";

        /// <summary>
        /// The logout uri.
        /// </summary>
        public const string LogoutUri = "/.webfront/c/logout";

        /// <summary>
        /// The clear token uri.
        /// </summary>
        public const string TokenExplainUri = "/.webfront/token";

        /// <summary>
        /// The start login uri.
        /// </summary>
        public const string StartLoginUri = "/.webfront/c/startLogin";


        /// <summary>
        /// Gets the <see cref="IAuthenticationTypeSystem"/>.
        /// </summary>
        /// <param name="server">This server.</param>
        /// <returns>The <see cref="IAuthenticationTypeSystem"/>.</returns>
        public static IAuthenticationTypeSystem GetAuthenticationTypeSystem( this RunningAspNetServer server ) => server.Services.GetRequiredService<IAuthenticationTypeSystem>();

        /// <summary>
        /// Gets the <see cref="WebFrontAuthOptions"/>.
        /// </summary>
        /// <param name="server">This server.</param>
        /// <returns>The authentication options.</returns>
        public static WebFrontAuthOptions GetAuthenticationOptions( this RunningAspNetServer server )
        {
            var o = server.Services.GetRequiredService<IOptionsMonitor<WebFrontAuthOptions>>();
            return o.Get( WebFrontAuthOptions.OnlyAuthenticationScheme );
        }

        /// <summary>
        /// Calls <see cref="RefreshUri"/> and returns the server response.
        /// </summary>
        /// <param name="client">This client.</param>
        /// <param name="withVersion">True to return the version.</param>
        /// <param name="withSchemes">True to return the available authentication schemes.</param>
        /// <returns>The server response.</returns>
        public static async Task<AuthServerResponse> AuthenticationRefreshAsync( this RunningAspNetServer.RunningClient client, bool withVersion = false, bool withSchemes = false )
        {
            var url = RefreshUri;
            if( withVersion && withSchemes )
            {
                url += "?version&schemes";
            }
            else if( withVersion ) url += "?version";
            else if( withSchemes ) url += "?schemes";
            using HttpResponseMessage tokenRefresh = await client.GetAsync( url );
            tokenRefresh.EnsureSuccessStatusCode();
            return await HandleResponseAsync( client, tokenRefresh );
        }

        static async Task<AuthServerResponse> HandleResponseAsync( RunningAspNetServer.RunningClient client, HttpResponseMessage m )
        {
            var r = AuthServerResponse.Parse( client.Server.GetAuthenticationTypeSystem(), await m.Content.ReadAsStringAsync() );
            client.Token = r.Token;
            return r;
        }

        /// <summary>
        /// Gets <see cref="LogoutUri"/>. This clears the <see cref="RunningAspNetServer.RunningClient.Token"/>.
        /// </summary>
        /// <param name="client">This client.</param>
        /// <returns>The awaitable.</returns>
        public static async Task AuthenticationLogoutAsync( this RunningAspNetServer.RunningClient client )
        {
            using HttpResponseMessage nop = await client.GetAsync( LogoutUri );
            client.Token = null;
        }

        /// <summary>
        /// Calls <see cref="ImpersonateUri"/> and returns the server response if it is successful.
        /// </summary>
        /// <param name="client">This client.</param>
        /// <param name="userName">The user name to impersonate.</param>
        /// <returns>The server response or null if impersonation failed.</returns>
        public static async Task<AuthServerResponse?> AuthenticationImpersonateAsync( this RunningAspNetServer.RunningClient client, string userName )
        {
            using HttpResponseMessage tokenRefresh = await client.PostJsonAsync( ImpersonateUri, $$"""{"userName":"{{userName}}"}""" );
            return tokenRefresh.StatusCode == System.Net.HttpStatusCode.OK
                    ? await HandleResponseAsync( client, tokenRefresh )
                    : null;
        }

        /// <summary>
        /// Calls <see cref="ImpersonateUri"/> and returns the server response if it is successful.
        /// </summary>
        /// <param name="client">This client.</param>
        /// <param name="userId">The user identifier to impersonate.</param>
        /// <returns>The server response or null if impersonation failed.</returns>
        public static async Task<AuthServerResponse?> AuthenticationImpersonateAsync( this RunningAspNetServer.RunningClient client, int userId )
        {
            using HttpResponseMessage tokenRefresh = await client.PostJsonAsync( ImpersonateUri, $$"""{"userId":{{userId}}}""" );
            return tokenRefresh.StatusCode == System.Net.HttpStatusCode.OK
                    ? await HandleResponseAsync( client, tokenRefresh )
                    : null;
        }

        /// <summary>
        /// Calls <see cref="BasicLoginUri"/> (or <see cref="UnsafeDirectLoginUri"/> if <paramref name="useGenericWrapper"/> is true)
        /// and check the <paramref name="expectSuccess"/> and cookies set by the server.
        /// </summary>
        /// <param name="client">This client.</param>
        /// <param name="userName">The user name.</param>
        /// <param name="expectSuccess">True if the login must succeed, false otherwise.</param>
        /// <param name="useGenericWrapper">True to use the <see cref="UnsafeDirectLoginUri"/> on Basic scheme.</param>
        /// <param name="rememberMe">False to not remember the authentication.</param>
        /// <param name="impersonateActualUser">True to impersonate the current user.</param>
        /// <param name="jsonUserData">Optional user data (will be in <see cref="AuthServerResponse.UserData"/>.</param>
        /// <param name="password">Password to use.</param>
        /// <returns>The server response.</returns>
        public static async Task<AuthServerResponse> AuthenticationBasicLoginAsync( this RunningAspNetServer.RunningClient client,
                                                                                    string userName,
                                                                                    bool expectSuccess,
                                                                                    bool useGenericWrapper = false,
                                                                                    bool rememberMe = true,
                                                                                    bool impersonateActualUser = false,
                                                                                    string? jsonUserData = null,
                                                                                    string password = "success" )
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
                        body = $$"""{"Provider":"Basic", "RememberMe":true, "ImpersonateActualUser":true, "Payload": {"userName":"{{userName}}","password":"{{password}}"}""";
                    }
                    else
                    {
                        body = $$"""{"Provider":"Basic", "RememberMe":true, "Payload": {"userName":"{{userName}}","password":"{{password}}"}""";
                    }
                }
                else
                {
                    if( impersonateActualUser )
                    {
                        body = $$"""{"Provider":"Basic", "ImpersonateActualUser":true, "Payload": {"userName":"{{userName}}","password":"{{password}}"}""";
                    }
                    else
                    {
                        body = $$"""{"Provider":"Basic", "Payload": {"userName":"{{userName}}","password":"{{password}}"}""";
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
                        body = $$"""{"userName":"{{userName}}", "password":"{{password}}", "rememberMe":true, "impersonateActualUser":true""";
                    }
                    else
                    {
                        body = $$"""{"userName":"{{userName}}", "password":"{{password}}", "rememberMe":true""";
                    }
                }
                else
                {
                    if( impersonateActualUser )
                    {
                        body = $$"""{"userName":"{{userName}}", "password":"{{password}}","ImpersonateActualUser":true""";
                    }
                    else
                    {
                        body = $$"""{"userName":"{{userName}}", "password":"{{password}}" """;
                    }
                }
            }
            if( jsonUserData != null )
            {
                body += $$""", "userData": {{jsonUserData}}""";
            }
            body += "}";
            using HttpResponseMessage responseMessage = await client.PostJsonAsync( uri, body );
            // Even when login failed, the Status is 200 and the response is here.
            responseMessage.EnsureSuccessStatusCode();
            var response = await HandleResponseAsync( client, responseMessage );
            Throw.DebugAssert( response.Info != null );
            if( expectSuccess )
            {
                response.Info.Level.Should().BeOneOf( AuthLevel.Normal, AuthLevel.Critical );
                response.Info.ActualUser.UserName.Should().Be( userName );
                CheckClientCookies( client, response, rememberMe );
            }
            else
            {
                // TODO: Precise the login failure behavior (make it configurable?).
                CheckClientCookies( client, response, rememberMe );
            }
            return response;

            static void CheckClientCookies( RunningAspNetServer.RunningClient client, AuthServerResponse response, bool expectedRememberMe )
            {
                var options = client.Server.GetAuthenticationOptions();
                var cookieName = options.AuthCookieName;
                var ltCookieName = cookieName + "LT";
                switch( options.CookieMode )
                {
                    case AuthenticationCookieMode.WebFrontPath:
                        {
                            client.CookieContainer.GetCookies( client.BaseAddress ).Should().BeEmpty();
                            var allCookies = client.CookieContainer.GetCookies( new Uri( client.BaseAddress, "/.webfront/c/" ) );
                            allCookies.Should().HaveCount( 2 );
                            CookieIsNotTheSameAsToken( allCookies, cookieName, response );
                            CheckLongTermCookie( expectedRememberMe, allCookies, ltCookieName );
                            break;
                        }
                    case AuthenticationCookieMode.RootPath:
                        {
                            var allCookies = client.CookieContainer.GetCookies( client.BaseAddress );
                            allCookies.Should().HaveCount( 2 );
                            CookieIsNotTheSameAsToken( allCookies, cookieName, response );
                            CheckLongTermCookie( expectedRememberMe, allCookies, ltCookieName );
                            break;
                        }
                    case AuthenticationCookieMode.None:
                        {
                            // RemmeberMe returned by the server is always false when CookieMode is None.
                            expectedRememberMe = false;
                            client.CookieContainer.GetCookies( client.BaseAddress ).Should().BeEmpty();
                            client.CookieContainer.GetCookies( new Uri( client.BaseAddress, "/.webfront/c/" ) ).Should().BeEmpty();
                            break;
                        }
                }
                response.RememberMe.Should().Be( expectedRememberMe );

                static void CheckLongTermCookie( bool rememberMe, System.Net.CookieCollection all, string cookieName )
                {
                    var cookie = all.Single( c => c.Name == cookieName ).Value;
                    cookie = HttpUtility.UrlDecode( cookie );
                    var longTerm = JObject.Parse( cookie );
                    ((string?)longTerm[StdAuthenticationTypeSystem.DeviceIdKeyType]).Should().NotBeNullOrEmpty( "There is always a non empty 'device' member." );
                    longTerm.ContainsKey( StdAuthenticationTypeSystem.UserIdKeyType ).Should().Be( rememberMe, "The user is here only when remember is true." );
                }

                static void CookieIsNotTheSameAsToken( System.Net.CookieCollection all, string cookieName, AuthServerResponse r )
                {
                    var cookie = all.Single( c => c.Name == cookieName ).Value;
                    cookie = HttpUtility.UrlDecode( cookie );
                    cookie.Should().NotBe( r.Token );
                }
            }
        }

        /// <summary>
        /// Reads the authentication cookie and long term cookie.
        /// </summary>
        /// <param name="client">This client.</param>
        /// <returns>The cookie information.</returns>
        public static AuthenticationCookieValues AuthenticationReadCookies( this RunningAspNetServer.RunningClient client )
        {
            var options = GetAuthenticationOptions( client.Server );
            System.Net.CookieCollection? all = null;
            switch( options.CookieMode )
            {
                case AuthenticationCookieMode.WebFrontPath:
                    {
                        all = client.CookieContainer.GetCookies( new Uri( client.BaseAddress, "/.webfront/c/" ) );
                        break;
                    }
                case AuthenticationCookieMode.RootPath:
                    {
                        all = client.CookieContainer.GetCookies( client.BaseAddress );
                        break;
                    }
                default:
                    Throw.DebugAssert( options.CookieMode == AuthenticationCookieMode.None );
                    break;
            }

            string? authCookie = all?.SingleOrDefault( c => c.Name == options.AuthCookieName )?.Value;
            JObject? ltCookie = null;
            string? ltDeviceId = null;
            string? ltUserId = null;
            string? ltUserName = null;

            var ltCookieStr = all?.SingleOrDefault( c => c.Name == options.AuthCookieName + "LT" )?.Value;
            if( ltCookieStr != null )
            {
                ltCookieStr = HttpUtility.UrlDecode( ltCookieStr );
                ltCookie = JObject.Parse( ltCookieStr );
                ltDeviceId = (string?)ltCookie[StdAuthenticationTypeSystem.DeviceIdKeyType];
                ltUserId = (string?)ltCookie[StdAuthenticationTypeSystem.UserIdKeyType];
                ltUserName = (string?)ltCookie[StdAuthenticationTypeSystem.UserNameKeyType];
            }
            return (authCookie, ltCookie, ltDeviceId, ltUserId, ltUserName);
        }

    }
}
