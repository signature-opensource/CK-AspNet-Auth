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
using System.Diagnostics;

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
        public async Task a_successful_basic_login_returns_valid_info_and_token_Async()
        {
            using( var s = new AuthServer() )
            {
                HttpResponseMessage response = await s.Client.PostJSON( basicLoginUri, "{\"userName\":\"Albert\",\"password\":\"success\"}" );
                response.EnsureSuccessStatusCode();
                var c = RefreshResponse.Parse( s.TypeSystem, await response.Content.ReadAsStringAsync() );
                Debug.Assert( c.Info != null );
                c.Info.User.UserId.Should().Be( 2 );
                c.Info.User.UserName.Should().Be( "Albert" );
                c.Info.User.Schemes.Should().HaveCount( 1 );
                c.Info.User.Schemes[0].Name.Should().Be( "Basic" );
                c.Info.User.Schemes[0].LastUsed.Should().BeCloseTo( DateTime.UtcNow, TimeSpan.FromMilliseconds( 1500 ) );
                c.Info.ActualUser.Should().BeSameAs( c.Info.User );
                c.Info.Level.Should().Be( AuthLevel.Normal );
                c.Info.IsImpersonated.Should().BeFalse();
                c.Token.Should().NotBeNullOrWhiteSpace();
                c.Refreshable.Should().BeFalse( "Since by default Options.SlidingExpirationTime is 0." );
            }
        }

        [Test]
        public async Task basic_login_is_404NotFound_when_no_BasicAuthenticationProvider_exists_Async()
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
        public async Task successful_login_set_the_cookies_on_the_webfront_c_path_and_these_cookies_can_be_used_to_restore_the_authentication_Async(
            AuthenticationCookieMode mode,
            bool useGenericWrapper )
        {
            using( var s = new AuthServer( opt => opt.CookieMode = mode,
                                           services =>
                                           {
                                               if( useGenericWrapper )
                                               {
                                                   services.AddSingleton<IWebFrontAuthUnsafeDirectLoginAllowService,BasicDirectLoginAllower>();
                                               }
                                           } ) )
            {
                // Login: the 2 cookies are set on .webFront/c/ path.
                var login = await s.LoginAlbertViaBasicProviderAsync( useGenericWrapper );
                Debug.Assert( login.Info != null );
                DateTime basicLoginTime = login.Info.User.Schemes.Single( p => p.Name == "Basic" ).LastUsed;
                string? originalToken = login.Token;
                // Request with token: the authentication is based on the token.
                {
                    s.Client.Token = originalToken;
                    HttpResponseMessage tokenRefresh = await s.Client.Get( refreshUri );
                    tokenRefresh.EnsureSuccessStatusCode();
                    var c = RefreshResponse.Parse( s.TypeSystem, await tokenRefresh.Content.ReadAsStringAsync() );
                    Debug.Assert( c.Info != null );
                    c.Info.Level.Should().Be( AuthLevel.Normal );
                    c.Info.User.UserName.Should().Be( "Albert" );
                    c.Info.User.Schemes.Single( p => p.Name == "Basic" ).LastUsed.Should().Be( basicLoginTime );
                }
                // Token less request: the authentication is restored from the cookie.
                {
                    s.Client.Token = null;
                    HttpResponseMessage tokenLessRefresh = await s.Client.Get( refreshUri );
                    tokenLessRefresh.EnsureSuccessStatusCode();
                    var c = RefreshResponse.Parse( s.TypeSystem, await tokenLessRefresh.Content.ReadAsStringAsync() );
                    Debug.Assert( c.Info != null );
                    c.Info.Level.Should().Be( AuthLevel.Normal );
                    c.Info.User.UserName.Should().Be( "Albert" );
                    c.Info.User.Schemes.Single( p => p.Name == "Basic" ).LastUsed.Should().Be( basicLoginTime );
                }
                // Request with token and ?schemes query parametrers: we receive the providers.
                {
                    s.Client.Token = originalToken;
                    HttpResponseMessage tokenRefresh = await s.Client.Get( refreshUri + "?schemes" );
                    tokenRefresh.EnsureSuccessStatusCode();
                    var c = RefreshResponse.Parse( s.TypeSystem, await tokenRefresh.Content.ReadAsStringAsync() );
                    Debug.Assert( c.Info != null );
                    c.Info.Level.Should().Be( AuthLevel.Normal );
                    c.Info.User.UserName.Should().Be( "Albert" );
                    c.Info.User.Schemes.Single( p => p.Name == "Basic" ).LastUsed.Should().Be( basicLoginTime );
                    c.Schemes.Should().ContainSingle( "Basic" );
                }
            }
        }

        [TestCase( AuthenticationCookieMode.WebFrontPath )]
        [TestCase( AuthenticationCookieMode.RootPath )]
        public async Task bad_tokens_are_ignored_as_long_as_cookies_can_be_used_Async( AuthenticationCookieMode mode )
        {
            using( var s = new AuthServer( opt => opt.CookieMode = mode ) )
            {
                var firstLogin = await s.LoginAlbertViaBasicProviderAsync();

                string badToken = firstLogin.Token + 'B';
                s.Client.Token = badToken;
                RefreshResponse c = await s.CallRefreshEndPointAsync();
                c.Info.Should().BeEquivalentTo( firstLogin.Info, "Authentication has been restored from cookies." );

                c.Token.Should().NotBeNullOrWhiteSpace( "Regenerated token differs." );
            }
        }

        [TestCase( AuthenticationCookieMode.WebFrontPath, true )]
        [TestCase( AuthenticationCookieMode.RootPath, true )]
        [TestCase( AuthenticationCookieMode.WebFrontPath, false )]
        [TestCase( AuthenticationCookieMode.RootPath, false )]
        public async Task logout_removes_both_cookies_Async( AuthenticationCookieMode mode, bool logoutWithToken )
        {
            using( var s = new AuthServer( opt => opt.CookieMode = mode ) )
            {
                // Login: the 2 cookies are set.
                var firstLogin = await s.LoginAlbertViaBasicProviderAsync();
                DateTime basicLoginTime = firstLogin.Info.User.Schemes.Single( p => p.Name == "Basic" ).LastUsed;
                string originalToken = firstLogin.Token;
                // Logout 
                if( logoutWithToken ) s.Client.Token = originalToken;
                HttpResponseMessage logout = await s.Client.Get( logoutUri );
                logout.EnsureSuccessStatusCode();
                // Refresh: no authentication.
                s.Client.Token = null;
                HttpResponseMessage tokenRefresh = await s.Client.Get( refreshUri );
                tokenRefresh.EnsureSuccessStatusCode();
                var c = RefreshResponse.Parse( s.TypeSystem, await tokenRefresh.Content.ReadAsStringAsync() );
                c.Info.Level.Should().Be( AuthLevel.None );
            }
        }

        [Test]
        public async Task invalid_payload_to_basic_login_returns_a_400_bad_request_Async()
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
        public async Task webfront_token_endpoint_returns_the_current_authentication_indented_JSON_and_enables_to_test_actual_authentication_Async( bool rootCookiePath )
        {
            using( var s = new AuthServer( opt => opt.CookieMode = rootCookiePath ? AuthenticationCookieMode.RootPath : AuthenticationCookieMode.WebFrontPath ) )
            {
                HttpResponseMessage auth = await s.Client.PostJSON( basicLoginUri, "{\"userName\":\"Albert\",\"password\":\"success\"}" );
                var c = RefreshResponse.Parse( s.TypeSystem, await auth.Content.ReadAsStringAsync() );
                {
                    // With token: it always works.
                    s.Client.Token = c.Token;
                    HttpResponseMessage req = await s.Client.Get( tokenExplainUri );
                    var tokenClear = await req.Content.ReadAsStringAsync();
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


        [TestCase( true, false )]
        [TestCase( true, true )]
        [TestCase( false, true )]
        [TestCase( false, false )]
        public async Task SlidingExpiration_works_as_expected_in_bearer_only_mode_by_calling_refresh_endpoint_Async( bool useGenericWrapper, bool rememberMe )
        {
            using( var s = new AuthServer( opt =>
            {
                opt.ExpireTimeSpan = TimeSpan.FromSeconds( 2.0 );
                opt.SlidingExpirationTime = TimeSpan.FromSeconds( 10 );
                opt.CookieMode = AuthenticationCookieMode.None;
            }, services =>
            {
                if( useGenericWrapper )
                {
                    services.AddSingleton<IWebFrontAuthUnsafeDirectLoginAllowService, BasicDirectLoginAllower>();
                }
            } ) )
            {
                // This test is far from perfect but does the job without clock injection.
                RefreshResponse auth = await s.LoginAlbertViaBasicProviderAsync( useGenericWrapper, rememberMe );
                DateTime next = auth.Info.Expires.Value - TimeSpan.FromSeconds( 1.7 );
                while( next > DateTime.UtcNow ) ;

                s.Client.Token = auth.Token;
                RefreshResponse refresh = await s.CallRefreshEndPointAsync();
                refresh.Info.Expires.Value.Should().BeAfter( auth.Info.Expires.Value, "Refresh increased the expiration time." );

                refresh.RememberMe.Should().BeFalse( "In CookieMode None, RememberMe is always false, no matter what." );
            }
        }

        [Test]
        public async Task SlidingExpiration_works_as_expected_in_rooted_Cookie_mode_where_any_request_can_do_the_job_Async()
        {
            using( var s = new AuthServer( opt =>
            {
                opt.CookieMode = AuthenticationCookieMode.RootPath;
                opt.ExpireTimeSpan = TimeSpan.FromSeconds( 2.0 );
                opt.SlidingExpirationTime = TimeSpan.FromSeconds( 10 );
            } ) )
            {
                // This test is far from perfect but does the job without clock injection.
                RefreshResponse auth = await s.LoginAlbertViaBasicProviderAsync();
                DateTime expCookie1 = s.Client.Cookies.GetCookies( s.Server.BaseAddress )[".webFront"].Expires.ToUniversalTime();
                expCookie1.Should().BeCloseTo( auth.Info.Expires.Value, precision: TimeSpan.FromSeconds( 1 ) );
                DateTime next = auth.Info.Expires.Value - TimeSpan.FromSeconds( 1.7 );
                while( next > DateTime.UtcNow ) ;

                // Calling token endpoint (like any other endpoint that sollicitates authentication) is enough.
                HttpResponseMessage req = await s.Client.Get( tokenExplainUri );
                var response = JObject.Parse( await req.Content.ReadAsStringAsync() );

                ((bool)response["rememberMe"]).Should().BeTrue();
                IAuthenticationInfo refresh = s.TypeSystem.AuthenticationInfo.FromJObject( (JObject)response["info"] );

                refresh.Expires.Value.Should().BeAfter( auth.Info.Expires.Value, "Token life time has been increased." );

                DateTime expCookie2 = s.Client.Cookies.GetCookies( s.Server.BaseAddress )[".webFront"].Expires.ToUniversalTime();
                expCookie2.Should().BeCloseTo( refresh.Expires.Value, precision: TimeSpan.FromSeconds( 1 ) );
            }
        }

        [Test]
        public async Task AllowedReturnUrls_quick_test_Async()
        {
            using( var s = new AuthServer( opt =>
            {
                opt.AllowedReturnUrls.Add( "https://yes.yes" );
            } ) )
            {
                // This scheme is not known but the test of the return url is done before.
                var m = await s.Client.Get( AuthServer.StartLoginUri + "?scheme=NONE&returnUrl=" + WebUtility.UrlEncode( "https://no.no" ) );
                m.StatusCode.Should().Be( HttpStatusCode.BadRequest );
                (await m.Content.ReadAsStringAsync()).Should()
                    .Be( @"{""errorId"":""DisallowedReturnUrl"",""errorText"":""The returnUrl='https://no.no' doesn't start with any of configured AllowedReturnUrls prefixes.""}" );

                // Currently invalid schemes throws (error 500 in real host).
                await FluentActions.Awaiting( () => s.Client.Get( AuthServer.StartLoginUri + "?scheme=NONE&returnUrl=" + WebUtility.UrlEncode( "https://yes.yes" ) ) )
                    .Should().ThrowAsync<Exception>();

                await FluentActions.Awaiting( () => s.Client.Get( AuthServer.StartLoginUri + "?scheme=NONE&returnUrl=" + WebUtility.UrlEncode( "https://yes.yes/hello" ) ) )
                    .Should().ThrowAsync<Exception>();

            }
        }


        [Test]
        public async Task empty_AllowedReturnUrls_forbids_any_inline_login_Async()
        {
            using( var s = new AuthServer() )
            {
                // This scheme is not known but the test of the return url is done before.
                var m = await s.Client.Get( AuthServer.StartLoginUri + "?scheme=NONE&returnUrl=" + WebUtility.UrlEncode( "https://un.reg.ister.ed" ) );
                m.StatusCode.Should().Be( HttpStatusCode.BadRequest );
                (await m.Content.ReadAsStringAsync()).Should()
                    .Be( @"{""errorId"":""DisallowedReturnUrl"",""errorText"":""The returnUrl='https://un.reg.ister.ed' doesn't start with any of configured AllowedReturnUrls prefixes.""}" );
            }
        }

    }
}
