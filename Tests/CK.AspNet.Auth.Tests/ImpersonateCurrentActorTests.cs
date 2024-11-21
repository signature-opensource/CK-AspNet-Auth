using CK.Auth;
using CK.Core;
using CK.Testing;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using System;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AspNet.Auth.Tests;

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

    class ImpersonationAllowAliceToAlbert : IWebFrontAuthImpersonationService
    {
        readonly FakeWebFrontAuthLoginService _loginService;

        public ImpersonationAllowAliceToAlbert( FakeWebFrontAuthLoginService loginService )
        {
            _loginService = loginService;
        }

        public Task<IUserInfo?> ImpersonateAsync( HttpContext ctx, IActivityMonitor monitor, IAuthenticationInfo info, int userId )
        {
            return Task.FromResult( DoAllow( info, userId ) );
        }

        public Task<IUserInfo?> ImpersonateAsync( HttpContext ctx, IActivityMonitor monitor, IAuthenticationInfo info, string userName )
        {
            return Task.FromResult( DoAllow( info, userName ) );
        }

        IUserInfo? DoAllow( IAuthenticationInfo info, object nameOrId )
        {
            if( info.ActualUser.UserName == "Alice" )
            {
                var target = nameOrId is int id
                                ? _loginService.UserDatabase.AllUsers.FirstOrDefault( u => u.UserId == id )
                                : _loginService.UserDatabase.AllUsers.FirstOrDefault( u => u.UserName == (string)nameOrId );
                // Alice is allowed to impersonate Albert.
                if( target != null && target.UserName == "Albert" )
                {
                    return target;
                }
            }
            return null;
        }

    }

    [TestCase( true )]
    [TestCase( false )]
    public async Task impersonateActualUser_parameter_can_login_and_impersonate_the_already_logged_user_Async( bool useGenericWrapper )
    {
        await using var runningServer = await LocalHelper.CreateLocalAuthServerAsync(
            configureServices: services =>
            {
                if( useGenericWrapper )
                {
                    services.AddSingleton<IWebFrontAuthUnsafeDirectLoginAllowService, BasicDirectLoginAllower>();
                }
                services.AddSingleton<IWebFrontAuthImpersonationService, ImpersonationAllowAliceToAlbert>();
            } );

        var r1 = await runningServer.Client.AuthenticationBasicLoginAsync( "Albert", true, useGenericWrapper: useGenericWrapper );
        Throw.DebugAssert( r1.Info != null );
        r1.Info.ActualUser.UserName.Should().Be( "Albert" );
        r1.Info.User.UserName.Should().Be( "Albert" );
        r1.Info.IsImpersonated.Should().BeFalse();

        var r2 = await runningServer.Client.AuthenticationBasicLoginAsync( "Alice", true, useGenericWrapper: useGenericWrapper, impersonateActualUser: true );
        Throw.DebugAssert( r2.Info != null );
        r2.Info.ActualUser.UserName.Should().Be( "Alice", "Alice is now the actual user." );
        r2.Info.User.UserName.Should().Be( "Albert", "Alice is impersonating Albert." );
        r2.Info.IsImpersonated.Should().BeTrue();

        // Impersonate to Alice: this clears the impersonation.
        AuthServerResponse? r = await runningServer.Client.AuthenticationImpersonateAsync( "Alice" );
        Throw.DebugAssert( r?.Info != null );
        r.Info.User.UserName.Should().Be( "Alice" );
        r.Info.ActualUser.UserName.Should().Be( "Alice" );
        r.Info.IsImpersonated.Should().BeFalse();
    }

    [TestCase( true )]
    [TestCase( false )]
    public async Task impersonateActualUser_parameter_is_harmless_when_the_user_is_already_logged_or_no_user_is_already_logged_Async( bool useGenericWrapper )
    {
        await using var runningServer = await LocalHelper.CreateLocalAuthServerAsync(
            services =>
            {
                if( useGenericWrapper )
                {
                    services.AddSingleton<IWebFrontAuthUnsafeDirectLoginAllowService, BasicDirectLoginAllower>();
                }
            } );

        var r1 = await runningServer.Client.AuthenticationBasicLoginAsync( "Albert", true, useGenericWrapper: useGenericWrapper, impersonateActualUser: true );
        Throw.DebugAssert( r1.Info != null );
        r1.Info.Level.Should().Be( CK.Auth.AuthLevel.Normal );
        r1.Info.ActualUser.UserName.Should().Be( "Albert" );
        r1.Info.User.UserName.Should().Be( "Albert" );
        r1.Info.IsImpersonated.Should().BeFalse();

        var r2 = await runningServer.Client.AuthenticationBasicLoginAsync( "Albert", true, useGenericWrapper: useGenericWrapper, impersonateActualUser: true );
        Throw.DebugAssert( r2.Info != null );
        r2.Info.Level.Should().Be( CK.Auth.AuthLevel.Normal );
        r2.Info.ActualUser.UserName.Should().Be( "Albert" );
        r2.Info.User.UserName.Should().Be( "Albert" );
        r2.Info.IsImpersonated.Should().BeFalse();
    }

    [TestCase( true, true, false )]
    [TestCase( false, true, false )]
    [TestCase( true, false, false )]
    [TestCase( false, false, false )]
    [TestCase( true, true, true )]
    [TestCase( false, true, true )]
    [TestCase( true, false, true )]
    [TestCase( false, false, true )]
    public async Task user_can_clear_its_own_impersonation_by_impersonating_to_itself_Async( bool byUserId,
                                                                                             bool useLoginToLeaveImpersonation,
                                                                                             bool useLoginCommand )
    {
        await using var runningServer = await LocalHelper.CreateLocalAuthServerAsync(
            services =>
            {
                services.AddSingleton<IWebFrontAuthImpersonationService, ImpersonationAllowAliceToAlbert>();
            } );

        // Login Albert.
        var initial = await (useLoginCommand
                                ? runningServer.Client.LoginViaLocalCommandAsync( "Albert" )
                                : runningServer.Client.AuthenticationBasicLoginAsync( "Albert", true ));
        Throw.DebugAssert( initial.Info != null );
        initial.Info.IsImpersonated.Should().BeFalse();
        initial.Info.User.UserName.Should().Be( "Albert" );

        // Alice impersonates Albert.
        var imp = await (useLoginCommand
                            ? runningServer.Client.LoginViaLocalCommandAsync( "Alice", impersonateActualUser: true )
                            : runningServer.Client.AuthenticationBasicLoginAsync( "Alice", true, impersonateActualUser: true ));
        Throw.DebugAssert( imp.Info != null );
        imp.Info.IsImpersonated.Should().BeTrue();
        imp.Info.ActualUser.UserName.Should().Be( "Alice" );
        imp.Info.User.UserName.Should().Be( "Albert" );

        if( useLoginToLeaveImpersonation )
        {
            // When Alice re-logs herself, the impersonation is cleared.
            // impersonateActualUser doesn't matter.
            bool impersonateActualUser = Environment.TickCount % 2 == 0;
            imp = await (useLoginCommand
                            ? runningServer.Client.LoginViaLocalCommandAsync( "Alice", impersonateActualUser: true )
                            : runningServer.Client.AuthenticationBasicLoginAsync( "Alice", true, impersonateActualUser: true ));
            Throw.DebugAssert( imp.Info != null );
            imp.Info.IsImpersonated.Should().BeFalse();
            imp.Info.ActualUser.UserName.Should().Be( "Alice" );
        }
        else
        {
            // When Alice impersonates to Alice, the impersonation is cleared.
            var r = byUserId
                    ? await runningServer.Client.AuthenticationImpersonateAsync( imp.Info.ActualUser.UserId )
                    : await runningServer.Client.AuthenticationImpersonateAsync( "Alice" );
            Throw.DebugAssert( r?.Info != null );
            r.Info.IsImpersonated.Should().BeFalse();
            r.Info.User.UserName.Should().Be( "Alice" );
        }
    }

}
