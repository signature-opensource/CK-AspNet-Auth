using CK.Core;
using CK.Testing;
using Shouldly;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace CK.AspNet.Auth.Tests;

[TestFixture]
public class RememberMeTests
{
    [TestCase( true, false )]
    [TestCase( true, true )]
    [TestCase( false, true )]
    [TestCase( false, false )]
    public async Task remember_me_sets_appropriate_cookies_Async( bool useGenericWrapper, bool rememberMe )
    {
        //
        // Note: SlidingExpiration_works_as_expected_in_bearer_only_mode_by_calling_refresh_endpoint
        //       test challenges the None cookie mode and the rememberMe option.
        //
        await using var runningServer = await LocalHelper.CreateLocalAuthServerAsync( services =>
        {
            // To support useGenericWrapper = true, we need to allow UnsafeDirectLogin.
            if( useGenericWrapper )
            {
                services.AddSingleton<IWebFrontAuthUnsafeDirectLoginAllowService, AllDirectLoginAllower>();
            }
        } );

        var options = new WebFrontAuthOptions();
        AuthServerResponse r = await runningServer.Client.AuthenticationBasicLoginAsync( "Albert", true, useGenericWrapper: useGenericWrapper, rememberMe: rememberMe );
        Throw.DebugAssert( r.Info != null );
        r.Info.User.UserName.ShouldBe( "Albert" );
        r.RememberMe.ShouldBe( rememberMe );
        var cookies = runningServer.Client.CookieContainer.GetCookies( new Uri( $"{runningServer.ServerAddress}/.webfront/c/" ) );
        cookies.Count.ShouldBe( 2 );
        if( rememberMe )
        {
            cookies.ShouldBe( all => all.All( c => c.Expires > DateTime.UtcNow ) );
        }
        else
        {
            var authCookie = cookies.Single( c => c.Name == options.AuthCookieName );
            authCookie.Expires.ShouldBe( DateTime.MinValue, "RememberMe is false: the authentication cookie uses a session lifetime." );
        }
    }

}
