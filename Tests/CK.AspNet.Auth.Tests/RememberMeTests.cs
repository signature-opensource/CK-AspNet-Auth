using CK.Core;
using CK.Testing;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace CK.AspNet.Auth.Tests
{
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
            RefreshResponse r = await runningServer.Client.LoginViaBasicProviderAsync( "Albert", true, useGenericWrapper: useGenericWrapper, rememberMe: rememberMe );
            Throw.DebugAssert( r.Info != null );
            r.Info.User.UserName.Should().Be( "Albert" );
            r.RememberMe.Should().Be( rememberMe );
            var cookies = runningServer.Client.CookieContainer.GetCookies( new Uri( $"{runningServer.ServerAddress}/.webfront/c/" ) );
            cookies.Should().HaveCount( 2 );
            if( rememberMe )
            {
                cookies.Should().Match( all => all.All( c => c.Expires > DateTime.UtcNow ) );
            }
            else
            {
                var authCookie = cookies.Single( c => c.Name == options.AuthCookieName );
                authCookie.Expires.Should().Be( DateTime.MinValue, "RememberMe is false: the authentication cookie uses a session lifetime." );
            }
        }

    }
}
