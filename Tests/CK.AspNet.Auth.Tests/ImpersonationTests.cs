using CK.Core;
using CK.Testing;
using Shouldly;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace CK.AspNet.Auth.Tests;

[TestFixture]
public class ImpersonationTests
{
    [Test]
    public async Task when_no_impersonation_service_is_registered_404_NotFound_Async()
    {
        await using var runningServer = await LocalHelper.CreateLocalAuthServerAsync();

        using HttpResponseMessage m1 = await runningServer.Client.PostJsonAsync( RunningAspNetAuthServerExtensions.ImpersonateUri, """{ "userName": "Robert" }""" );
        m1.StatusCode.ShouldBe( HttpStatusCode.NotFound );

        await runningServer.Client.AuthenticationBasicLoginAsync( "Alice", true );
        using HttpResponseMessage m2 = await runningServer.Client.PostJsonAsync( RunningAspNetAuthServerExtensions.ImpersonateUri, """{ "userName": "Robert" }""" );
        m2.StatusCode.ShouldBe( HttpStatusCode.NotFound );
    }

    [Test]
    public async Task user_can_always_clear_its_own_impersonation_even_if_no_impersonation_service_exists_Async()
    {
        await using var runningServer = await LocalHelper.CreateLocalAuthServerAsync();

        await runningServer.Client.AuthenticationBasicLoginAsync( "Albert", true );

        var r = await runningServer.Client.AuthenticationImpersonateAsync( "Albert" );
        Throw.DebugAssert( r?.Info != null );
        r.Info.IsImpersonated.ShouldBeFalse();
        r.Info.User.UserName.ShouldBe( "Albert" );
        r.Info.ActualUser.UserName.ShouldBe( "Albert" );
    }

    [TestCase( true )]
    [TestCase( false )]
    public async Task user_can_clear_its_own_impersonation_by_impersonating_to_itself_Async( bool byUserId )
    {
        await using var runningServer = await LocalHelper.CreateLocalAuthServerAsync(
            services =>
            {
                services.AddSingleton<IWebFrontAuthImpersonationService, ImpersonationForEverybodyService>();
            } );

        // Login Albert.
        await runningServer.Client.AuthenticationBasicLoginAsync( "Albert", true );
        // ...and impersonate Robert.
        var r = await runningServer.Client.AuthenticationImpersonateAsync( "Robert" );
        Throw.DebugAssert( r?.Info != null );
        r.Info.IsImpersonated.ShouldBeTrue();
        r.Info.User.UserName.ShouldBe( "Robert" );
        r.Info.ActualUser.UserName.ShouldBe( "Albert" );

        // Impersonating again in Robert: nothing changes.
        r = byUserId
                ? await runningServer.Client.AuthenticationImpersonateAsync( r.Info.User.UserId )
                : await runningServer.Client.AuthenticationImpersonateAsync( "Robert" );
        Throw.DebugAssert( r?.Info != null );
        r.Info.IsImpersonated.ShouldBeTrue();
        r.Info.User.UserName.ShouldBe( "Robert" );
        r.Info.ActualUser.UserName.ShouldBe( "Albert" );

        // When Albert impersonates to Albert, the impersonation is cleared.
        r = byUserId
                ? await runningServer.Client.AuthenticationImpersonateAsync( r.Info.ActualUser.UserId )
                : await runningServer.Client.AuthenticationImpersonateAsync( "Albert" );
        Throw.DebugAssert( r?.Info != null );
        r.Info.IsImpersonated.ShouldBeFalse();
        r.Info.User.UserName.ShouldBe( "Albert" );
        r.Info.ActualUser.UserName.ShouldBe( "Albert" );
    }

    [Test]
    public async Task anonymous_can_not_impersonate_with_403_Forbidden_but_allowed_user_can_with_200_OK_Async()
    {
        await using var runningServer = await LocalHelper.CreateLocalAuthServerAsync(
            services =>
            {
                services.AddSingleton<IWebFrontAuthImpersonationService, ImpersonationForEverybodyService>();
            } );

        using HttpResponseMessage m = await runningServer.Client.PostJsonAsync( RunningAspNetAuthServerExtensions.ImpersonateUri, @"{ ""userName"": ""Robert"" }" );
        m.StatusCode.ShouldBe( HttpStatusCode.Forbidden );

        await runningServer.Client.AuthenticationBasicLoginAsync( "Albert", true );
        var r = await runningServer.Client.AuthenticationImpersonateAsync( "Robert" );
        Throw.DebugAssert( r?.Info != null );
        r.Info.IsImpersonated.ShouldBeTrue();
        r.Info.User.UserName.ShouldBe( "Robert" );
        r.Info.ActualUser.UserName.ShouldBe( "Albert" );
    }

    [Test]
    public async Task impersonate_can_be_called_with_userId_instead_of_userName_Async()
    {
        await using var runningServer = await LocalHelper.CreateLocalAuthServerAsync(
            services =>
            {
                services.AddSingleton<IWebFrontAuthImpersonationService, ImpersonationForEverybodyService>();
            } );

        await runningServer.Client.AuthenticationBasicLoginAsync( "Alice", true );
        var r = await runningServer.Client.AuthenticationImpersonateAsync( 3712 );
        Throw.DebugAssert( r?.Info != null );
        r.Info.IsImpersonated.ShouldBeTrue();

        r.Info.User.UserId.ShouldBe( 3712 );
        r.Info.User.UserName.ShouldBe( "Albert" );

        r.Info.ActualUser.UserId.ShouldBe( 3711 );
        r.Info.ActualUser.UserName.ShouldBe( "Alice" );
    }

    [Test]
    public async Task impersonate_to_an_unknown_userName_or_userId_fails_with_403_Forbidden_Async()
    {
        await using var runningServer = await LocalHelper.CreateLocalAuthServerAsync(
            services =>
            {
                services.AddSingleton<IWebFrontAuthImpersonationService, ImpersonationForEverybodyService>();
            } );

        await runningServer.Client.AuthenticationBasicLoginAsync( "Albert", true );
        using HttpResponseMessage m1 = await runningServer.Client.PostJsonAsync( RunningAspNetAuthServerExtensions.ImpersonateUri, @"{ ""userId"": 1e34 }" );
        m1.StatusCode.ShouldBe( HttpStatusCode.Forbidden );

        using HttpResponseMessage m2 = await runningServer.Client.PostJsonAsync( RunningAspNetAuthServerExtensions.ImpersonateUri, @"{ ""userName"": ""kexistepas"" }" );
        m2.StatusCode.ShouldBe( HttpStatusCode.Forbidden );
    }

    [TestCase( "" )]
    [TestCase( "{" )]
    [TestCase( @"""not a json object""" )]
    [TestCase( @"{""name"":""n""}" )]
    [TestCase( @"{""id"":3}" )]
    [TestCase( @"{""userName"":3}" )]
    [TestCase( @"{""userId"": ""36bis""}" )]
    [TestCase( @"{""userName"":""Robert"",""userId"":3}" )]
    public async Task impersonate_with_invalid_body_fails_with_400_BadRequest_Async( string body )
    {
        await using var runningServer = await LocalHelper.CreateLocalAuthServerAsync(
            services =>
            {
                services.AddSingleton<IWebFrontAuthImpersonationService, ImpersonationForEverybodyService>();
            } );
        await runningServer.Client.AuthenticationBasicLoginAsync( "Albert", true );
        HttpResponseMessage m = await runningServer.Client.PostJsonAsync( RunningAspNetAuthServerExtensions.ImpersonateUri, body );
        m.StatusCode.ShouldBe( HttpStatusCode.BadRequest );
    }

}
