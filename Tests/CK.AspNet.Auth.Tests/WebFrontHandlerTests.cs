using CK.Auth;
using CK.Core;
using CK.Testing;
using Shouldly;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Newtonsoft.Json.Linq;
using NUnit.Framework;
using System;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace CK.AspNet.Auth.Tests;

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
        await using var runningServer = await LocalHelper.CreateLocalAuthServerAsync();

        HttpResponseMessage response = await runningServer.Client.PostJsonAsync( RunningAspNetAuthServerExtensions.BasicLoginUri, """{"userName":"Albert","password":"success"}""" );
        response.EnsureSuccessStatusCode();
        var r = AuthServerResponse.Parse( runningServer.GetAuthenticationTypeSystem(), await response.Content.ReadAsStringAsync() );
        Debug.Assert( r.Info != null );
        r.Info.User.UserId.ShouldBe( 3712 );
        r.Info.User.UserName.ShouldBe( "Albert" );
        r.Info.User.Schemes.Count.ShouldBe( 1 );
        r.Info.User.Schemes[0].Name.ShouldBe( "Basic" );
        r.Info.User.Schemes[0].LastUsed.ShouldBe( DateTime.UtcNow, tolerance: TimeSpan.FromMilliseconds( 1500 ) );
        r.Info.ActualUser.ShouldBeSameAs( r.Info.User );
        r.Info.Level.ShouldBe( AuthLevel.Normal );
        r.Info.IsImpersonated.ShouldBeFalse();
        r.Token.ShouldNotBeNullOrWhiteSpace();
        r.Refreshable.ShouldBeFalse( "Since by default Options.SlidingExpirationTime is 0." );
    }

    [Test]
    public async Task basic_login_is_404NotFound_when_no_BasicAuthenticationProvider_exists_Async()
    {
        // This replaces the IWebFrontAuthLoginService (the last added one wins).
        await using var runningServer = await LocalHelper.CreateLocalAuthServerAsync( services => services.AddSingleton<IWebFrontAuthLoginService, NoSchemeLoginService>() );

        HttpResponseMessage response = await runningServer.Client.PostJsonAsync( RunningAspNetAuthServerExtensions.BasicLoginUri, """{"userName":"Albert","password":"success"}""" );
        response.StatusCode.ShouldBe( HttpStatusCode.NotFound );
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
    public async Task successful_login_set_the_cookies_on_the_webfront_c_path_and_these_cookies_can_be_used_to_restore_the_authentication_Async( AuthenticationCookieMode mode,
                                                                                                                                                 bool useGenericWrapper )
    {
        await using var runningServer = await LocalHelper.CreateLocalAuthServerAsync(
                                       services =>
                                       {
                                           if( useGenericWrapper )
                                           {
                                               services.AddSingleton<IWebFrontAuthUnsafeDirectLoginAllowService, BasicDirectLoginAllower>();
                                           }
                                       },
                                       webFrontAuthOptions: opt => opt.CookieMode = mode );

        // Login: the 2 cookies are set on .webFront/c/ path.
        var login = await runningServer.Client.AuthenticationBasicLoginAsync( "Albert", true, useGenericWrapper: useGenericWrapper );
        Debug.Assert( login.Info != null );
        DateTime basicLoginTime = login.Info.User.Schemes.Single( p => p.Name == "Basic" ).LastUsed;
        string? originalToken = login.Token;
        // Request with token: the authentication is based on the token.
        {
            runningServer.Client.Token = originalToken;
            using HttpResponseMessage tokenRefresh = await runningServer.Client.GetAsync( RunningAspNetAuthServerExtensions.RefreshUri );
            tokenRefresh.EnsureSuccessStatusCode();
            var c = AuthServerResponse.Parse( runningServer.GetAuthenticationTypeSystem(), await tokenRefresh.Content.ReadAsStringAsync() );
            Debug.Assert( c.Info != null );
            c.Info.Level.ShouldBe( AuthLevel.Normal );
            c.Info.User.UserName.ShouldBe( "Albert" );
            c.Info.User.Schemes.Single( p => p.Name == "Basic" ).LastUsed.ShouldBe( basicLoginTime );
        }
        // Token less request: the authentication is restored from the cookie.
        {
            runningServer.Client.Token = null;
            var tokenLessResponse = await runningServer.Client.AuthenticationRefreshAsync();
            Debug.Assert( tokenLessResponse.Info != null );
            tokenLessResponse.Info.Level.ShouldBe( AuthLevel.Normal );
            tokenLessResponse.Info.User.UserName.ShouldBe( "Albert" );
            tokenLessResponse.Info.User.Schemes.Single( p => p.Name == "Basic" ).LastUsed.ShouldBe( basicLoginTime );
        }
        // Request with token and ?schemes query parametrers: we receive the providers.
        {
            runningServer.Client.Token = originalToken;
            var tokenRefresh = await runningServer.Client.AuthenticationRefreshAsync( schemes: true );
            Debug.Assert( tokenRefresh.Info != null );
            tokenRefresh.Info.Level.ShouldBe( AuthLevel.Normal );
            tokenRefresh.Info.User.UserName.ShouldBe( "Albert" );
            tokenRefresh.Info.User.Schemes.Single( p => p.Name == "Basic" ).LastUsed.ShouldBe( basicLoginTime );
            tokenRefresh.Schemes.ShouldHaveSingleItem().ShouldBe( "Basic" );
        }
    }

    [TestCase( AuthenticationCookieMode.WebFrontPath )]
    [TestCase( AuthenticationCookieMode.RootPath )]
    public async Task bad_tokens_are_ignored_as_long_as_cookies_can_be_used_Async( AuthenticationCookieMode mode )
    {
        await using var runningServer = await LocalHelper.CreateLocalAuthServerAsync( webFrontAuthOptions: opt => opt.CookieMode = mode );

        var firstLogin = await runningServer.Client.AuthenticationBasicLoginAsync( "Albert", true );

        string badToken = firstLogin.Token + 'B';
        runningServer.Client.Token = badToken;
        AuthServerResponse c = await runningServer.Client.AuthenticationRefreshAsync();
        c.Info.ShouldBeEquivalentTo( firstLogin.Info, "Authentication has been restored from cookies." );
        c.Token.ShouldNotBe( badToken );
    }

    [TestCase( AuthenticationCookieMode.WebFrontPath, true )]
    [TestCase( AuthenticationCookieMode.RootPath, true )]
    [TestCase( AuthenticationCookieMode.WebFrontPath, false )]
    [TestCase( AuthenticationCookieMode.RootPath, false )]
    public async Task logout_removes_both_cookies_Async( AuthenticationCookieMode mode, bool logoutWithToken )
    {
        await using var runningServer = await LocalHelper.CreateLocalAuthServerAsync( webFrontAuthOptions: opt => opt.CookieMode = mode );

        // Login: the 2 cookies are set.
        var firstLogin = await runningServer.Client.AuthenticationBasicLoginAsync( "Albert", true );
        Throw.DebugAssert( firstLogin.Info != null );
        DateTime basicLoginTime = firstLogin.Info.User.Schemes.Single( p => p.Name == "Basic" ).LastUsed;
        runningServer.Client.Token.ShouldBe( firstLogin.Token, "The LoginViaBasicProviderAsync updates the client.Token." );

        // Logout 
        if( !logoutWithToken ) runningServer.Client.Token = null;

        await runningServer.Client.AuthenticationLogoutAsync();
        runningServer.Client.Token.ShouldBeNull( "The AuthenticationLogout() clears the client token." );

        // Refresh: no authentication.
        var r = await runningServer.Client.AuthenticationRefreshAsync();
        Throw.DebugAssert( r.Info != null );
        r.Info.Level.ShouldBe( AuthLevel.None );
    }

    [TestCase( AuthenticationCookieMode.WebFrontPath, true )]
    [TestCase( AuthenticationCookieMode.RootPath, true )]
    [TestCase( AuthenticationCookieMode.WebFrontPath, false )]
    [TestCase( AuthenticationCookieMode.RootPath, false )]
    public async Task LogoutCommand_removes_both_cookies_Async( AuthenticationCookieMode mode, bool logoutWithToken )
    {
        await using var runningServer = await LocalHelper.CreateLocalAuthServerAsync( webFrontAuthOptions: opt => opt.CookieMode = mode );

        // Login: the 2 cookies are set.
        var firstLogin = await runningServer.Client.AuthenticationBasicLoginAsync( "Albert", true );
        Throw.DebugAssert( firstLogin.Info != null );
        DateTime basicLoginTime = firstLogin.Info.User.Schemes.Single( p => p.Name == "Basic" ).LastUsed;
        runningServer.Client.Token.ShouldBe( firstLogin.Token, "The LoginViaBasicProviderAsync updates the client.Token." );

        // Logout 
        if( !logoutWithToken ) runningServer.Client.Token = null;

        using HttpResponseMessage logout = await runningServer.Client.GetAsync( "ComingFromCris/LogoutCommand" );
        logout.EnsureSuccessStatusCode();

        // Refresh: no authentication.
        runningServer.Client.Token = null;
        var r = await runningServer.Client.AuthenticationRefreshAsync();
        Throw.DebugAssert( r.Info != null );
        r.Info.Level.ShouldBe( AuthLevel.None );
    }

    [Test]
    public async Task invalid_payload_to_basic_login_returns_a_400_bad_request_Async()
    {
        await using var runningServer = await LocalHelper.CreateLocalAuthServerAsync();

        HttpResponseMessage response = await runningServer.Client.PostJsonAsync( RunningAspNetAuthServerExtensions.BasicLoginUri, "{\"userName\":\"\",\"password\":\"success\"}" );
        response.StatusCode.ShouldBe( HttpStatusCode.BadRequest );
        runningServer.Client.CookieContainer.GetCookies( new Uri( $"{runningServer.ServerAddress}/.webfront/c/" ) ).Count.ShouldBe( 0 );
        response = await runningServer.Client.PostJsonAsync( RunningAspNetAuthServerExtensions.BasicLoginUri, "{\"userName\":\"toto\",\"password\":\"\"}" );
        response.StatusCode.ShouldBe( HttpStatusCode.BadRequest );
        response = await runningServer.Client.PostJsonAsync( RunningAspNetAuthServerExtensions.BasicLoginUri, "not a json" );
        response.StatusCode.ShouldBe( HttpStatusCode.BadRequest );
    }

    [TestCase( false, Description = "With cookies on the .webfront path." )]
    [TestCase( true, Description = "With cookies on the root path." )]
    public async Task webfront_token_endpoint_returns_the_current_authentication_indented_JSON_and_enables_to_test_actual_authentication_Async( bool rootCookiePath )
    {
        await using var runningServer = await LocalHelper.CreateLocalAuthServerAsync( webFrontAuthOptions: opt => opt.CookieMode = rootCookiePath
                                                                                                                  ? AuthenticationCookieMode.RootPath
                                                                                                                  : AuthenticationCookieMode.WebFrontPath );
        var r = await runningServer.Client.AuthenticationBasicLoginAsync( "Albert", true );
        {
            // With token: it always works.
            runningServer.Client.Token.ShouldBe( r.Token );
            HttpResponseMessage req = await runningServer.Client.GetAsync( tokenExplainUri );
            var tokenClear = await req.Content.ReadAsStringAsync();
            tokenClear.ShouldContain( "Albert" );
        }
        {
            // Without token: it works only when CookieMode is AuthenticationCookieMode.RootPath.
            runningServer.Client.Token = null;
            HttpResponseMessage req = await runningServer.Client.GetAsync( RunningAspNetAuthServerExtensions.TokenExplainUri );
            var tokenClear = await req.Content.ReadAsStringAsync();
            if( rootCookiePath )
            {
                // Authentication Cookie has been used.
                tokenClear.ShouldContain( "Albert" );
            }
            else
            {
                tokenClear.ShouldNotContain( "Albert" );
            }
        }
    }

    [TestCase( true, false )]
    [TestCase( true, true )]
    [TestCase( false, true )]
    [TestCase( false, false )]
    public async Task SlidingExpiration_works_as_expected_in_bearer_only_mode_by_calling_refresh_endpoint_Async( bool useGenericWrapper, bool rememberMe )
    {
        await using var runningServer = await LocalHelper.CreateLocalAuthServerAsync(
            services =>
            {
                if( useGenericWrapper )
                {
                    services.AddSingleton<IWebFrontAuthUnsafeDirectLoginAllowService, BasicDirectLoginAllower>();
                }
            },
            webFrontAuthOptions: opt =>
            {
                opt.ExpireTimeSpan = TimeSpan.FromSeconds( 2.0 );
                opt.SlidingExpirationTime = TimeSpan.FromSeconds( 10 );
                opt.CookieMode = AuthenticationCookieMode.None;
            } );

        // This test is far from perfect but does the job without clock injection.
        AuthServerResponse auth = await runningServer.Client.AuthenticationBasicLoginAsync( "Albert", true, useGenericWrapper, rememberMe );
        Throw.DebugAssert( auth.Info!.Expires != null );

        DateTime next = auth.Info.Expires.Value - TimeSpan.FromSeconds( 1.7 );
        while( next > DateTime.UtcNow ) ;

        runningServer.Client.Token = auth.Token;
        AuthServerResponse refresh = await runningServer.Client.AuthenticationRefreshAsync();
        Throw.DebugAssert( refresh.Info!.Expires != null );
        refresh.Info.Expires.Value.ShouldBeGreaterThan( auth.Info.Expires.Value.AddSeconds( 1 ), "Refresh increased the expiration time." );

        refresh.RememberMe.ShouldBeFalse( "In CookieMode None, RememberMe is always false, no matter what." );
    }

    [Test]
    public async Task SlidingExpiration_works_as_expected_in_rooted_Cookie_mode_where_any_request_can_do_the_job_Async()
    {
        await using var runningServer = await LocalHelper.CreateLocalAuthServerAsync( webFrontAuthOptions: opt =>
        {
            opt.CookieMode = AuthenticationCookieMode.RootPath;
            opt.ExpireTimeSpan = TimeSpan.FromSeconds( 2.0 );
            opt.SlidingExpirationTime = TimeSpan.FromSeconds( 10 );
        } );

        // This test is far from perfect but does the job without clock injection.
        AuthServerResponse auth = await runningServer.Client.AuthenticationBasicLoginAsync( "Albert", true );
        Throw.DebugAssert( auth.Info!.Expires != null );

        DateTime expCookie1 = runningServer.Client.CookieContainer.GetCookies( runningServer.Client.BaseAddress )[".webFront"]!.Expires.ToUniversalTime();
        expCookie1.ShouldBe( auth.Info.Expires.Value, tolerance: TimeSpan.FromSeconds( 1 ) );

        DateTime next = auth.Info.Expires.Value - TimeSpan.FromSeconds( 1.7 );
        while( next > DateTime.UtcNow ) ;

        // Calling token endpoint (like any other endpoint that sollicitates authentication) is enough.
        using HttpResponseMessage req = await runningServer.Client.GetAsync( RunningAspNetAuthServerExtensions.TokenExplainUri );
        var response = JObject.Parse( await req.Content.ReadAsStringAsync() );

        ((bool?)response["rememberMe"]).ShouldNotBeNull().ShouldBeTrue();
        IAuthenticationInfo? refresh = runningServer.GetAuthenticationTypeSystem().AuthenticationInfo.FromJObject( (JObject?)response["info"] );
        Throw.DebugAssert( refresh!.Expires != null );

        refresh.Expires.Value.ShouldBeGreaterThan( auth.Info.Expires.Value, "Token life time has been increased." );
        Throw.DebugAssert( refresh.Expires != null );

        DateTime expCookie2 = runningServer.Client.CookieContainer.GetCookies( runningServer.Client.BaseAddress )[".webFront"]!.Expires.ToUniversalTime();
        expCookie2.ShouldBe( refresh.Expires.Value, tolerance: TimeSpan.FromSeconds( 1 ) );
    }

    [Test]
    public async Task AllowedReturnUrls_quick_test_Async()
    {
        await using var runningServer = await LocalHelper.CreateLocalAuthServerAsync( webFrontAuthOptions: opt =>
        {
            opt.AllowedReturnUrls.Add( "https://yes.yes" );
        } );

        {
            // This scheme is not known but the test of the return url is done before.
            using var m = await runningServer.Client.GetAsync( RunningAspNetAuthServerExtensions.StartLoginUri + "?scheme=NONE&returnUrl=" + WebUtility.UrlEncode( "https://no.no" ) );
            m.StatusCode.ShouldBe( HttpStatusCode.BadRequest );
            (await m.Content.ReadAsStringAsync()).ShouldBe( """{"errorId":"DisallowedReturnUrl","errorText":"The returnUrl='https://no.no' doesn't start with any of configured AllowedReturnUrls prefixes."}""" );

            // Invalid schemes triggers an error 500 in AspNet ChallengeAsync.
            // The exception is "No authentication handler is registered for the scheme 'NONE'. The registered schemes are: WebFrontAuth. Did you forget to call AddAuthentication().Add[SomeAuthHandler]("NONE",...)?"
            // TODO: since our scheme is provided by the front, we SHOULD test the available schemes and return a 400 instead of a 500.
            using var m2 = await runningServer.Client.GetAsync( RunningAspNetAuthServerExtensions.StartLoginUri + "?scheme=NONE&returnUrl=" + WebUtility.UrlEncode( "https://yes.yes" ) );
            m2.StatusCode.ShouldBe( HttpStatusCode.InternalServerError );

            using var m3 = await runningServer.Client.GetAsync( RunningAspNetAuthServerExtensions.StartLoginUri + "?scheme=NONE&returnUrl=" + WebUtility.UrlEncode( "https://yes.yes/hello" ) );
            m3.StatusCode.ShouldBe( HttpStatusCode.InternalServerError );
        }
    }

    [Test]
    public async Task empty_AllowedReturnUrls_forbids_any_inline_login_Async()
    {
        await using var runningServer = await LocalHelper.CreateLocalAuthServerAsync();

        // This scheme is not known but the test of the return url is done before.
        using var m = await runningServer.Client.GetAsync( RunningAspNetAuthServerExtensions.StartLoginUri + "?scheme=NONE&returnUrl=" + WebUtility.UrlEncode( "https://un.reg.ister.ed" ) );
        m.StatusCode.ShouldBe( HttpStatusCode.BadRequest );
        (await m.Content.ReadAsStringAsync()).ShouldBe( """{"errorId":"DisallowedReturnUrl","errorText":"The returnUrl='https://un.reg.ister.ed' doesn't start with any of configured AllowedReturnUrls prefixes."}""" );
    }

}
