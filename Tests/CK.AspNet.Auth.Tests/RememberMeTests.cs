using CK.Core;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CK.AspNet.Auth.Tests
{
    public class RememberMeTests
    {
        class AllDirectLoginAllower : IWebFrontAuthUnsafeDirectLoginAllowService
        {
            public Task<bool> AllowAsync( HttpContext ctx, IActivityMonitor monitor, string scheme, object payload ) => Task.FromResult( true );
        }

        [TestCase( true, false )]
        [TestCase( true, true )]
        [TestCase( false, true )]
        [TestCase( false, false )]
        public async Task remember_me_sets_no_LongTerm_cookie_and_a_Session_cookie( bool useGenericWrapper, bool rememberMe )
        {
            // The SlidingExpiration_works_as_expected_in_bearer_only_mode_by_calling_refresh_endpoint test challenges the None cookie mode and the rememberMe option.
            using( var s = new AuthServer( configureServices: services =>
            {
                if( useGenericWrapper )
                {
                    services.AddSingleton<IWebFrontAuthUnsafeDirectLoginAllowService, AllDirectLoginAllower>();
                }
            } ) )
            {
                RefreshResponse auth = await s.LoginAlbertViaBasicProvider( useGenericWrapper, rememberMe );
                auth.Info.User.UserName.Should().Be( "Albert" );
                auth.RememberMe.Should().Be( rememberMe );
                var cookies = s.Client.Cookies.GetCookies( new Uri( s.Server.BaseAddress, "/.webfront/c/" ) );
                if( rememberMe )
                {
                    cookies.Should().HaveCount( 2 );
                    cookies.Should().Match( all => all.All( c => c.Expires > DateTime.MinValue ) );
                }
                else
                {
                    cookies.Should().HaveCount( 1 );
                    cookies[0].Expires.Should().Be( DateTime.MinValue );
                }
            }
        }

    }
}
