using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
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
            // Note: the SlidingExpiration_works_as_expected_in_bearer_only_mode_by_calling_refresh_endpoint test challenges the
            // None cookie mode and the rememberMe option.
            using( var s = new AuthServer( configureServices: services =>
            {
                // To support useGenericWrapper = true, we need to allow UnsafeDirectLogin.
                if( useGenericWrapper )
                {
                    services.AddSingleton<IWebFrontAuthUnsafeDirectLoginAllowService, AllDirectLoginAllower>();
                }
            } ) )
            {
                var options = new WebFrontAuthOptions();
                RefreshResponse auth = await s.LoginAlbertViaBasicProviderAsync( useGenericWrapper, rememberMe );
                auth.Info.User.UserName.Should().Be( "Albert" );
                auth.RememberMe.Should().Be( rememberMe );
                var cookies = s.Client.Cookies.GetCookies( new Uri( s.Server.BaseAddress, "/.webfront/c/" ) );
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
}
