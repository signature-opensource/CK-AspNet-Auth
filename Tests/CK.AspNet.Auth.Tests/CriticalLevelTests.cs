using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using CK.Auth;
using CK.Core;
using CK.Testing;
using Shouldly;
using NUnit.Framework;

namespace CK.AspNet.Auth.Tests;

[TestFixture]
public class CriticalLevelTests
{
    [Test]
    public async Task when_no_dictionary_is_set_returns_normal_Async()
    {
        await using var runningServer = await LocalHelper.CreateLocalAuthServerAsync( webFrontAuthOptions: options => options.ExpireTimeSpan = TimeSpan.FromHours( 1 ) );

        var response = await runningServer.Client.AuthenticationBasicLoginAsync( "Albert", true );
        Throw.DebugAssert( response.Info != null );
        response.Info.Level.ShouldBe( AuthLevel.Normal );
        response.Info.Expires.ShouldNotBeNull().ShouldBe( DateTime.UtcNow + TimeSpan.FromHours( 1 ), TimeSpan.FromSeconds( 60 ) );
        response.Info.CriticalExpires.HasValue.ShouldBeFalse();
    }

    [Test]
    public async Task when_dictionary_has_no_matching_key_returns_normal_Async()
    {
        // Ignored (hopefully).
        var scts = new Dictionary<string, TimeSpan> { { "SomeScheme", TimeSpan.FromHours( 1 ) } };

        void SetOptions( WebFrontAuthOptions options )
        {
            options.ExpireTimeSpan = TimeSpan.FromHours( 1 );
            options.SchemesCriticalTimeSpan = scts;
        }

        await using var runningServer = await LocalHelper.CreateLocalAuthServerAsync( webFrontAuthOptions: SetOptions );

        var response = await runningServer.Client.AuthenticationBasicLoginAsync( "Albert", true );
        Throw.DebugAssert( response.Info != null );
        response.Info.Level.ShouldBe( AuthLevel.Normal );
        response.Info.Expires.ShouldNotBeNull().ShouldBe( DateTime.UtcNow + TimeSpan.FromHours( 1 ), tolerance: TimeSpan.FromSeconds( 60 ) );
        response.Info.CriticalExpires.HasValue.ShouldBeFalse();

    }

    [Test]
    public async Task when_dictionary_has_matching_key_with_valid_value_returns_critical_Async()
    {
        var scts = new Dictionary<string, TimeSpan> { { "Basic", TimeSpan.FromHours( 1 ) } };

        void SetOptions( WebFrontAuthOptions options )
        {
            options.ExpireTimeSpan = TimeSpan.FromHours( 2 );
            options.SchemesCriticalTimeSpan = scts;
        }

        await using var runningServer = await LocalHelper.CreateLocalAuthServerAsync( webFrontAuthOptions: SetOptions );

        var response = await runningServer.Client.AuthenticationBasicLoginAsync( "Albert", true );
        Throw.DebugAssert( response.Info != null );
        response.Info.Level.ShouldBe( AuthLevel.Critical );
        response.Info.Expires.ShouldNotBeNull().ShouldBe( DateTime.UtcNow + TimeSpan.FromHours( 2 ), tolerance: TimeSpan.FromSeconds( 60 ) );
        response.Info.CriticalExpires.ShouldNotBeNull().ShouldBe( DateTime.UtcNow + TimeSpan.FromHours( 1 ), tolerance: TimeSpan.FromSeconds( 60 ) );

    }

    [Test]
    public async Task when_dictionary_has_matching_key_with_invalid_value_returns_normal_Async()
    {
        var scts = new Dictionary<string, TimeSpan> { { "Basic", TimeSpan.FromHours( -1 ) } };

        void SetOptions( WebFrontAuthOptions options )
        {
            options.ExpireTimeSpan = TimeSpan.FromHours( 1 );
            options.SchemesCriticalTimeSpan = scts;
        }

        await using var runningServer = await LocalHelper.CreateLocalAuthServerAsync( webFrontAuthOptions: SetOptions );

        var response = await runningServer.Client.AuthenticationBasicLoginAsync( "Albert", true );
        Throw.DebugAssert( response.Info != null );
        response.Info.Level.ShouldBe( AuthLevel.Normal );
        response.Info.Expires.ShouldNotBeNull().ShouldBe(DateTime.UtcNow + TimeSpan.FromHours(1), tolerance: TimeSpan.FromSeconds(60));
        response.Info.CriticalExpires.HasValue.ShouldBeFalse();
    }

    [Test]
    public async Task when_expires_is_shorter_than_critical_expires_then_expires_is_extended_Async()
    {
        var scts = new Dictionary<string, TimeSpan> { { "Basic", TimeSpan.FromHours( 2 ) } };

        void SetOptions( WebFrontAuthOptions options )
        {
            options.ExpireTimeSpan = TimeSpan.FromHours( 1 );
            options.SchemesCriticalTimeSpan = scts;
        }

        await using var runningServer = await LocalHelper.CreateLocalAuthServerAsync( webFrontAuthOptions: SetOptions );

        var response = await runningServer.Client.AuthenticationBasicLoginAsync( "Albert", true );
        Throw.DebugAssert( response.Info != null );
        response.Info.Level.ShouldBe( AuthLevel.Critical );
        response.Info.Expires.ShouldNotBeNull().ShouldBe(DateTime.UtcNow + TimeSpan.FromHours(2), tolerance: TimeSpan.FromSeconds(60));
        response.Info.CriticalExpires.ShouldNotBeNull().ShouldBe(DateTime.UtcNow + TimeSpan.FromHours(2), tolerance: TimeSpan.FromSeconds(60));
    }
}
