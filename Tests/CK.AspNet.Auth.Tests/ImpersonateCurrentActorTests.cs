using CK.Core;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace CK.AspNet.Auth.Tests
{
    [TestFixture]
    public class ImpersonateActualUserTests
    {
        class BasicDirectLoginAllower : IWebFrontAuthUnsafeDirectLoginAllowService
        {
            public Task<bool> AllowAsync( HttpContext ctx, IActivityMonitor monitor, string scheme, object payload )
            {
                return Task.FromResult( scheme == "Basic" );
            }
        }


        [TestCase( true )]
        [TestCase( false )]
        public async Task impersonateActualUser_parameter_can_login_and_impersonate_the_already_logged_user_Async( bool useGenericWrapper )
        {
            using( var s = new AuthServer( configureServices: services =>
            {
                if( useGenericWrapper )
                {
                    services.AddSingleton<IWebFrontAuthUnsafeDirectLoginAllowService, BasicDirectLoginAllower>();
                }
            } ) )
            {
                var r1 = await s.LoginViaBasicProviderAsync( "Albert", useGenericWrapper: useGenericWrapper );
                r1.Info.ActualUser.UserName.Should().Be( "Albert" );
                r1.Info.User.UserName.Should().Be( "Albert" );
                r1.Info.IsImpersonated.Should().BeFalse();

                var r2 = await s.LoginViaBasicProviderAsync( "Alice", useGenericWrapper: useGenericWrapper, impersonateActualUser: true );
                r2.Info.ActualUser.UserName.Should().Be( "Albert", "Albert is the actual user." );
                r2.Info.User.UserName.Should().Be( "Alice" );
                r2.Info.IsImpersonated.Should().BeTrue();

                // Impersonate to Albert: this clears the impersonation.
                HttpResponseMessage m = await s.Client.PostJSON( AuthServer.ImpersonateUri, @"{ ""userName"": ""Albert"" }" );
                m.EnsureSuccessStatusCode();
                string content = await m.Content.ReadAsStringAsync();
                RefreshResponse r = RefreshResponse.Parse( s.TypeSystem, content );
                r.Info.IsImpersonated.Should().BeFalse();
                r.Info.User.UserName.Should().Be( "Albert" );
                r.Info.ActualUser.UserName.Should().Be( "Albert" );
                r.Info.IsImpersonated.Should().BeFalse();
            }
        }

        [TestCase(true)]
        [TestCase(false)]
        public async Task impersonateActualUser_parameter_is_harmless_when_the_user_is_already_logged_or_no_user_is_already_logged_Async( bool useGenericWrapper )
        {
            using( var s = new AuthServer( configureServices: services =>
            {
                if( useGenericWrapper )
                {
                    services.AddSingleton<IWebFrontAuthUnsafeDirectLoginAllowService, BasicDirectLoginAllower>();
                }
            } ) )
            {
                var r1 = await s.LoginViaBasicProviderAsync( "Albert", useGenericWrapper: useGenericWrapper, impersonateActualUser: true );
                r1.Info.Level.Should().Be( CK.Auth.AuthLevel.Normal );
                r1.Info.ActualUser.UserName.Should().Be( "Albert" );
                r1.Info.User.UserName.Should().Be( "Albert" );
                r1.Info.IsImpersonated.Should().BeFalse();

                var r2 = await s.LoginViaBasicProviderAsync( "Albert", useGenericWrapper: useGenericWrapper, impersonateActualUser: true );
                r2.Info.Level.Should().Be( CK.Auth.AuthLevel.Normal );
                r2.Info.ActualUser.UserName.Should().Be( "Albert" );
                r2.Info.User.UserName.Should().Be( "Albert" );
                r2.Info.IsImpersonated.Should().BeFalse();
            }
        }

    }
}
