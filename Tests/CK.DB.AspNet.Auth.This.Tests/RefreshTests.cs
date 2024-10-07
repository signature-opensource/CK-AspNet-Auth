using CK.AspNet.Auth;
using CK.Core;
using CK.DB.Actor;
using CK.DB.Auth;
using CK.SqlServer;
using CK.Testing;
using FluentAssertions;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using NUnit.Framework;
using System;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.DB.AspNet.Auth.Tests;

[TestFixture]
public class RefreshTests
{
    [Test]
    public async Task refreshing_with_callBackend_correctly_handles_impersonation_changes_Async()
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Services.AddSingleton<IWebFrontAuthImpersonationService, ImpersonationForEverybodyService>();
        builder.AddApplicationIdentityServiceConfiguration();
        await using var runningServer = await builder.CreateRunningAspNetAuthenticationServerAsync( SharedEngine.Map );

        var user = runningServer.Services.GetRequiredService<UserTable>();
        var basic = runningServer.Services.GetRequiredService<IBasicAuthenticationProvider>();

        using var ctx = new SqlStandardCallContext( TestHelper.Monitor );

        int idAlbert = await SetupUserAsync( ctx, "Albert", "pass", user, basic );
        int idPaula = await SetupUserAsync( ctx, "Paula", "pass", user, basic );

        var r = await runningServer.Client.AuthenticationBasicLoginAsync( "Albert", true, password: "pass" );

        var newAlbertName = Guid.NewGuid().ToString();
        await user.UserNameSetAsync( ctx, 1, idAlbert, newAlbertName );

        r = await runningServer.Client.AuthenticationRefreshAsync( callBackend: true );
        Throw.DebugAssert( r.Info != null );
        r.Info.User.UserId.Should().Be( idAlbert );
        r.Info.User.UserName.Should().Be( newAlbertName );

        r = await runningServer.Client.AuthenticationImpersonateAsync( idPaula );
        Throw.DebugAssert( r.Info != null );
        r.Info.User.UserName.Should().Be( "Paula" );
        r.Info.ActualUser.UserName.Should().Be( newAlbertName );

        var rRefresh = await runningServer.Client.AuthenticationRefreshAsync();
        rRefresh.Info.Should().BeEquivalentTo( r.Info, o => o.Excluding( info => info.Expires ) );

        newAlbertName = Guid.NewGuid().ToString();
        var newPaulaName = Guid.NewGuid().ToString();
        await user.UserNameSetAsync( ctx, 1, idAlbert, newAlbertName );
        await user.UserNameSetAsync( ctx, 1, idPaula, newPaulaName );

        r = await runningServer.Client.AuthenticationRefreshAsync( callBackend: true );
        Throw.DebugAssert( r.Info != null );
        r.Info.User.UserName.Should().Be( newPaulaName );
        r.Info.ActualUser.UserName.Should().Be( newAlbertName );

        await user.UserNameSetAsync( ctx, 1, idPaula, "Paula" );
        r = await runningServer.Client.AuthenticationRefreshAsync( callBackend: true );
        Throw.DebugAssert( r.Info != null );
        r.Info.User.UserName.Should().Be( "Paula" );
        r.Info.ActualUser.UserName.Should().Be( newAlbertName );

        await user.UserNameSetAsync( ctx, 1, idAlbert, "Albert" );
        r = await runningServer.Client.AuthenticationImpersonateAsync( idAlbert );
        Throw.DebugAssert( r.Info != null );
        r.Info.User.UserId.Should().Be( idAlbert );
        r.Info.User.UserName.Should().Be( newAlbertName,
            "Impersonation in the ImpersonationForEverybodyService does not refresh the actual user." );

        r = await runningServer.Client.AuthenticationRefreshAsync( callBackend: true );
        Throw.DebugAssert( r.Info != null );
        r.Info.ActualUser.UserName.Should().Be( "Albert" );
    }

    static async Task<int> SetupUserAsync( SqlStandardCallContext ctx, string userName, string password, UserTable user, IBasicAuthenticationProvider basic )
    {
        int idUser = await user.CreateUserAsync( ctx, 1, userName );
        if( idUser == -1 ) idUser = await user.FindByNameAsync( ctx, userName );
        await basic.CreateOrUpdatePasswordUserAsync( ctx, 1, idUser, password );
        return idUser;
    }
}
