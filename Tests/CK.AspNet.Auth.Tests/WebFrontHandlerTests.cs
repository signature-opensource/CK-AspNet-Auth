using CK.AspNet.Tester;
using CK.Auth;
using FluentAssertions;
using Newtonsoft.Json.Linq;
using NUnit.Framework;
using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using CK.Core;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace CK.AspNet.Auth.Tests
{
    [TestFixture]
    public class WebFrontHandlerTests
    {
        const string basicLoginUri = "/.webfront/c/basicLogin";
        const string unsafeDirectLoginUri = "/.webfront/c/unsafeDirectLogin";
        const string refreshUri = "/.webfront/c/refresh";
        const string logoutUri = "/.webfront/c/logout";
        const string tokenExplainUri = "/.webfront/token";

        [Test]
        public async Task calling_c_refresh_from_scrath_returns_null_info_and_token()
        {
            using( var s = new AuthServer() )
            {
                HttpResponseMessage response = await s.Client.Get( refreshUri );
                response.EnsureSuccessStatusCode();
                var c = RefreshResponse.Parse( s.TypeSystem, response.Content.ReadAsStringAsync().Result );
                c.ShouldBeEquivalentTo( new RefreshResponse() );
            }
        }

        [Test]
        public async Task calling_c_refresh_from_scrath_with_providers_query_parameter_returns_null_info_and_null_token_but_the_array_of_providers_name()
        {
            using( var s = new AuthServer() )
            {
                HttpResponseMessage response = await s.Client.Get( refreshUri + "?schemes" );
                response.EnsureSuccessStatusCode();
                var c = RefreshResponse.Parse( s.TypeSystem, response.Content.ReadAsStringAsync().Result );
                c.ShouldBeEquivalentTo( new RefreshResponse() { Schemes = new[] { "Basic" } } );
            }
        }

        [Test]
        public async Task a_successful_basic_login_returns_valid_info_and_token()
        {
            using( var s = new AuthServer() )
            {
                HttpResponseMessage response = await s.Client.PostJSON( basicLoginUri, "{\"userName\":\"Albert\",\"password\":\"success\"}" );
                response.EnsureSuccessStatusCode();
                var c = RefreshResponse.Parse( s.TypeSystem, response.Content.ReadAsStringAsync().Result );
                c.Info.User.UserId.Should().Be( 2 );
                c.Info.User.UserName.Should().Be( "Albert" );
                c.Info.User.Schemes.Should().HaveCount( 1 );
                c.Info.User.Schemes[0].Name.Should().Be( "Basic" );
                c.Info.User.Schemes[0].LastUsed.Should().BeCloseTo( DateTime.UtcNow, 1500 );
                c.Info.ActualUser.Should().BeSameAs( c.Info.User );
                c.Info.Level.Should().Be( AuthLevel.Normal );
                c.Info.IsImpersonated.Should().BeFalse();
                c.Token.Should().NotBeNullOrWhiteSpace();
                c.Refreshable.Should().BeFalse( "Since by default Options.SlidingExpirationTime is 0." );
            }
        }

        [Test]
        public async Task basic_login_is_404NotFound_when_no_BasicAuthenticationProvider_exists()
        {
            using( var s = new AuthServer(configureServices: services => services.Replace<IWebFrontAuthLoginService, NoAuthWebFrontLoginService>() ) )
            {
                HttpResponseMessage response = await s.Client.PostJSON( basicLoginUri, "{\"userName\":\"Albert\",\"password\":\"success\"}" );
                response.StatusCode.Should().Be( HttpStatusCode.NotFound );
            }
        }

        class BasicDirectLoginAllower : IWebFrontAuthUnsafeDirectLoginAllowService
        {
            public Task<bool> AllowAsync( HttpContext ctx, IActivityMonitor monitor, string scheme, object payload )
            {
                return Task.FromResult( scheme == "Basic" );
            }
        }

        [TestCase( AuthenticationCookieMode.WebFrontPath, false )]
        [TestCase( AuthenticationCookieMode.RootPath, false )]
        [TestCase( AuthenticationCookieMode.WebFrontPath, true )]
        [TestCase( AuthenticationCookieMode.RootPath, true )]
        public async Task successful_login_set_the_cookies_on_the_webfront_c_path_and_these_cookies_can_be_used_to_restore_the_authentication( AuthenticationCookieMode mode, bool useGenericWrapper )
        {
            using( var s = new AuthServer(
                opt =>
            {
                opt.CookieMode = mode;
            },
            services =>
            {
                if( useGenericWrapper )
                {
                    services.AddSingleton<IWebFrontAuthUnsafeDirectLoginAllowService,BasicDirectLoginAllower>();
                }
            } ) )
            {
                // Login: the 2 cookies are set on .webFront/c/ path.
                var login = await s.LoginAlbertViaBasicProvider( useGenericWrapper );
                DateTime basicLoginTime = login.Info.User.Schemes.Single( p => p.Name == "Basic" ).LastUsed;
                string originalToken = login.Token;
                // Request with token: the authentication is based on the token.
                {
                    s.Client.Token = originalToken;
                    HttpResponseMessage tokenRefresh = await s.Client.Get( refreshUri );
                    tokenRefresh.EnsureSuccessStatusCode();
                    var c = RefreshResponse.Parse( s.TypeSystem, tokenRefresh.Content.ReadAsStringAsync().Result );
                    c.Info.Level.Should().Be( AuthLevel.Normal );
                    c.Info.User.UserName.Should().Be( "Albert" );
                    c.Info.User.Schemes.Single( p => p.Name == "Basic" ).LastUsed.Should().Be( basicLoginTime );
                }
                // Token less request: the authentication is restored from the cookie.
                {
                    s.Client.Token = null;
                    HttpResponseMessage tokenLessRefresh = await s.Client.Get( refreshUri );
                    tokenLessRefresh.EnsureSuccessStatusCode();
                    var c = RefreshResponse.Parse( s.TypeSystem, tokenLessRefresh.Content.ReadAsStringAsync().Result );
                    c.Info.Level.Should().Be( AuthLevel.Normal );
                    c.Info.User.UserName.Should().Be( "Albert" );
                    c.Info.User.Schemes.Single( p => p.Name == "Basic" ).LastUsed.Should().Be( basicLoginTime );
                }
                // Request with token and ?schemes query parametrers: we receive the providers.
                {
                    s.Client.Token = originalToken;
                    HttpResponseMessage tokenRefresh = await s.Client.Get( refreshUri + "?schemes" );
                    tokenRefresh.EnsureSuccessStatusCode();
                    var c = RefreshResponse.Parse( s.TypeSystem, tokenRefresh.Content.ReadAsStringAsync().Result );
                    c.Info.Level.Should().Be( AuthLevel.Normal );
                    c.Info.User.UserName.Should().Be( "Albert" );
                    c.Info.User.Schemes.Single( p => p.Name == "Basic" ).LastUsed.Should().Be( basicLoginTime );
                    c.Schemes.Should().ContainSingle( "Basic" );
                }
            }
        }

        [TestCase( AuthenticationCookieMode.WebFrontPath )]
        [TestCase( AuthenticationCookieMode.RootPath )]
        public async Task bad_tokens_are_ignored( AuthenticationCookieMode mode )
        {
            using( var s = new AuthServer( opt => opt.CookieMode = mode ) )
            {
                var firstLogin = await s.LoginAlbertViaBasicProvider();
                string badToken = firstLogin.Token + 'B';
                s.Client.Token = badToken;
                RefreshResponse c = await s.CallRefreshEndPoint();
                c.Info.Should().BeNull();
                HttpResponseMessage tokenRead = await s.Client.Get( tokenExplainUri );
                tokenRead.Content.ReadAsStringAsync().Result.Should().Be( "{}" );
            }
        }

        [TestCase( AuthenticationCookieMode.WebFrontPath, true )]
        [TestCase( AuthenticationCookieMode.RootPath, true )]
        [TestCase( AuthenticationCookieMode.WebFrontPath, false )]
        [TestCase( AuthenticationCookieMode.RootPath, false )]
        public async Task logout_without_full_query_parameter_removes_the_authentication_cookie_but_keeps_the_unsafe_one( AuthenticationCookieMode mode, bool logoutWithToken )
        {
            using( var s = new AuthServer( opt => opt.CookieMode = mode ) )
            {
                // Login: the 2 cookies are set.
                var firstLogin = await s.LoginAlbertViaBasicProvider();
                DateTime basicLoginTime = firstLogin.Info.User.Schemes.Single( p => p.Name == "Basic" ).LastUsed;
                string originalToken = firstLogin.Token;
                // Logout 
                if( logoutWithToken ) s.Client.Token = originalToken;
                HttpResponseMessage logout = await s.Client.Get( logoutUri );
                logout.EnsureSuccessStatusCode();
                // Refresh: we have the Unsafe Albert.
                s.Client.Token = null;
                RefreshResponse c = await s.CallRefreshEndPoint();
                c.Info.Level.Should().Be( AuthLevel.Unsafe );
                c.Info.User.UserName.Should().Be( "" );
                c.Info.UnsafeUser.UserName.Should().Be( "Albert" );
                c.Info.UnsafeUser.Schemes.Single( p => p.Name == "Basic" ).LastUsed.Should().Be( basicLoginTime );
            }
        }

        [TestCase( AuthenticationCookieMode.WebFrontPath, true )]
        [TestCase( AuthenticationCookieMode.RootPath, true )]
        [TestCase( AuthenticationCookieMode.WebFrontPath, false )]
        [TestCase( AuthenticationCookieMode.RootPath, false )]
        public async Task logout_with_full_query_parameter_removes_both_cookies( AuthenticationCookieMode mode, bool logoutWithToken )
        {
            using( var s = new AuthServer( opt => opt.CookieMode = mode ) )
            {
                // Login: the 2 cookies are set.
                var firstLogin = await s.LoginAlbertViaBasicProvider();
                DateTime basicLoginTime = firstLogin.Info.User.Schemes.Single( p => p.Name == "Basic" ).LastUsed;
                string originalToken = firstLogin.Token;
                // Logout 
                if( logoutWithToken ) s.Client.Token = originalToken;
                HttpResponseMessage logout = await s.Client.Get( logoutUri + "?full" );
                logout.EnsureSuccessStatusCode();
                // Refresh: no authentication.
                s.Client.Token = null;
                HttpResponseMessage tokenRefresh = await s.Client.Get( refreshUri );
                tokenRefresh.EnsureSuccessStatusCode();
                var c = RefreshResponse.Parse( s.TypeSystem, await tokenRefresh.Content.ReadAsStringAsync() );
                c.Info.Should().BeNull();
                c.Token.Should().BeNull();
            }
        }

        [Test]
        public async Task invalid_payload_to_basic_login_returns_a_400_bad_request()
        {
            using( var s = new AuthServer() )
            {
                HttpResponseMessage response = await s.Client.PostJSON( basicLoginUri, "{\"userName\":\"\",\"password\":\"success\"}" );
                response.StatusCode.Should().Be( HttpStatusCode.BadRequest );
                s.Client.Cookies.GetCookies( new Uri( s.Server.BaseAddress, "/.webfront/c/" ) ).Should().HaveCount( 0 );
                response = await s.Client.PostJSON( basicLoginUri, "{\"userName\":\"toto\",\"password\":\"\"}" );
                response.StatusCode.Should().Be( HttpStatusCode.BadRequest );
                response = await s.Client.PostJSON( basicLoginUri, "not a json" );
                response.StatusCode.Should().Be( HttpStatusCode.BadRequest );
            }
        }

        [TestCase( false, Description = "With cookies on the .webfront path." )]
        [TestCase( true, Description = "With cookies on the root path." )]
        public async Task webfront_token_endpoint_returns_the_current_authentication_indented_JSON_and_enables_to_test_actual_authentication( bool rootCookiePath )
        {
            using( var s = new AuthServer( opt => opt.CookieMode = rootCookiePath ? AuthenticationCookieMode.RootPath : AuthenticationCookieMode.WebFrontPath ) )
            {
                HttpResponseMessage auth = await s.Client.PostJSON( basicLoginUri, "{\"userName\":\"Albert\",\"password\":\"success\"}" );
                var c = RefreshResponse.Parse( s.TypeSystem, auth.Content.ReadAsStringAsync().Result );
                {
                    // With token: it always works.
                    s.Client.Token = c.Token;
                    HttpResponseMessage req = await s.Client.Get( tokenExplainUri );
                    var tokenClear = req.Content.ReadAsStringAsync().Result;
                    tokenClear.Should().Contain( "Albert" );
                }
                {
                    // Without token: it works only when CookieMode is AuthenticationCookieMode.RootPath.
                    s.Client.Token = null;
                    HttpResponseMessage req = await s.Client.Get( tokenExplainUri );
                    var tokenClear = await req.Content.ReadAsStringAsync();
                    if( rootCookiePath )
                    {
                        // Authentication Cookie has been used.
                        tokenClear.Should().Contain( "Albert" );
                    }
                    else
                    {
                        tokenClear.Should().NotContain( "Albert" );
                    }
                }
            }
        }


        [Test]
        public async Task SlidingExpiration_works_as_expected_in_bearer_only_mode_by_calling_refresh_endpoint()
        {
            
            using( var s = new AuthServer( opt =>
            {
                opt.ExpireTimeSpan = TimeSpan.FromSeconds( 2.0 );
                opt.SlidingExpirationTime = TimeSpan.FromSeconds( 10 );
            } ) )
            {
                // This test is far from perfect but does the job without clock injection.
                RefreshResponse auth = await s.LoginAlbertViaBasicProvider();
                DateTime next = auth.Info.Expires.Value - TimeSpan.FromSeconds( 1.7 );
                while( next > DateTime.UtcNow ) ;
                RefreshResponse refresh = await s.CallRefreshEndPoint();
                refresh.Info.Expires.Value.Should().BeAfter( auth.Info.Expires.Value, "Refresh increased the expiration time." );
            }
        }

        [Test]
        public async Task SlidingExpiration_works_as_expected_in_rooted_Cookie_mode_where_any_request_can_do_the_job()
        {
            using( var s = new AuthServer( opt =>
            {
                opt.CookieMode = AuthenticationCookieMode.RootPath;
                opt.ExpireTimeSpan = TimeSpan.FromSeconds( 2.0 );
                opt.SlidingExpirationTime = TimeSpan.FromSeconds( 10 );
            } ) )
            {
                // This test is far from perfect but does the job without clock injection.
                RefreshResponse auth = await s.LoginAlbertViaBasicProvider();
                DateTime expCookie1 = s.Client.Cookies.GetCookies( s.Server.BaseAddress )[".webFront"].Expires.ToUniversalTime();
                expCookie1.Should().BeCloseTo( auth.Info.Expires.Value, precision: 1000 );
                DateTime next = auth.Info.Expires.Value - TimeSpan.FromSeconds( 1.7 );
                while( next > DateTime.UtcNow ) ;

                // Calling token endpoint (like any other endpoint that sollicitates authentication) is enough.
                HttpResponseMessage req = await s.Client.Get( tokenExplainUri );
                IAuthenticationInfo refresh = s.TypeSystem.AuthenticationInfo.FromJObject( JObject.Parse( req.Content.ReadAsStringAsync().Result ) );
                refresh.Expires.Value.Should().BeAfter( auth.Info.Expires.Value, "Token life time has been increased." );

                DateTime expCookie2 = s.Client.Cookies.GetCookies( s.Server.BaseAddress )[".webFront"].Expires.ToUniversalTime();
                expCookie2.Should().BeCloseTo( refresh.Expires.Value, precision: 1000 );
            }
        }

    }
}
