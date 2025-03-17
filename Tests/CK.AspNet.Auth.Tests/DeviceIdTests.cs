using CK.Core;
using CK.Testing;
using Shouldly;
using NUnit.Framework;
using System.Threading.Tasks;

namespace CK.AspNet.Auth.Tests;

[TestFixture]
public class DeviceIdTests
{
    [Test]
    public async Task DeviceId_is_not_set_until_wefront_call_and_is_not_changed_Async()
    {
        await using var runningServer = await LocalHelper.CreateLocalAuthServerAsync();

        string? deviceId = null;
        {
            using var message = await runningServer.Client.GetAsync( "echo/outside" );
            var textMessage = await message.Content.ReadAsStringAsync();
            textMessage.ShouldBe( "/outside" );
            var cookies = runningServer.Client.AuthenticationReadCookies();
            cookies.AuthCookie.ShouldBeNull();
            cookies.LTDeviceId.ShouldBeNull();
            cookies.LTUserId.ShouldBeNull();
        }
        {
            await runningServer.Client.AuthenticationRefreshAsync();
            var cookies = runningServer.Client.AuthenticationReadCookies();
            cookies.AuthCookie.ShouldBeNull();
            cookies.LTDeviceId.ShouldNotBeNullOrEmpty();
            deviceId = cookies.LTDeviceId;
        }
        {
            using var message = await runningServer.Client.GetAsync( "echo/hop" );
            var textMessage = await message.Content.ReadAsStringAsync();
            textMessage.ShouldBe( "/hop" );
            var cookies = runningServer.Client.AuthenticationReadCookies();
            cookies.AuthCookie.ShouldBeNull();
            cookies.LTDeviceId.ShouldBe( deviceId );
        }
        {
            await runningServer.Client.AuthenticationRefreshAsync();
            var cookies = runningServer.Client.AuthenticationReadCookies();
            cookies.AuthCookie.ShouldBeNull();
            cookies.LTDeviceId.ShouldNotBeNullOrEmpty();
            cookies.LTDeviceId.ShouldBe( deviceId );
        }
    }

    [TestCase( true )]
    [TestCase( false )]
    public async Task DeviceId_is_independent_of_the_authentication_Async( bool callRefreshFirst )
    {
        await using var runningServer = await LocalHelper.CreateLocalAuthServerAsync();

        string? deviceId = null;
        {
            using var message = await runningServer.Client.GetAsync( "echo/none-yet" );
            var textMessage = await message.Content.ReadAsStringAsync();
            textMessage.ShouldBe( "/none-yet" );
            var cookies = runningServer.Client.AuthenticationReadCookies();
            cookies.AuthCookie.ShouldBeNull();
            cookies.LTDeviceId.ShouldBeNull();
            cookies.LTUserId.ShouldBeNull();
        }
        if( callRefreshFirst )
        {
            var refreshResponse = await runningServer.Client.AuthenticationRefreshAsync();
            Throw.DebugAssert( refreshResponse.Info != null );
            refreshResponse.Info.Level.ShouldBe( CK.Auth.AuthLevel.None );
            var cookies = runningServer.Client.AuthenticationReadCookies();
            cookies.AuthCookie.ShouldBeNull();
            cookies.LTDeviceId.ShouldNotBeNullOrWhiteSpace();
            deviceId = cookies.LTDeviceId;
        }
        {
            await runningServer.Client.AuthenticationBasicLoginAsync( "Albert", expectSuccess: true, rememberMe: false );
            var cookies = runningServer.Client.AuthenticationReadCookies();
            cookies.AuthCookie.ShouldNotBeNullOrWhiteSpace();
            cookies.LTDeviceId.ShouldNotBeNullOrWhiteSpace();
            if( callRefreshFirst )
            {
                cookies.LTDeviceId.ShouldBe( deviceId );
            }
            else deviceId = cookies.LTDeviceId;
        }
        {
            using var message = await runningServer.Client.GetAsync( "echo/hop" );
            var textMessage = await message.Content.ReadAsStringAsync();
            textMessage.ShouldBe( "/hop" );
            var cookies = runningServer.Client.AuthenticationReadCookies();
            cookies.AuthCookie.ShouldNotBeNullOrWhiteSpace();
            cookies.LTDeviceId.ShouldBe( deviceId );
        }
        {
            var refreshResponse = await runningServer.Client.AuthenticationRefreshAsync();
            Throw.DebugAssert( refreshResponse.Info != null );
            refreshResponse.Info.User.UserName.ShouldBe( "Albert" );
            var cookies = runningServer.Client.AuthenticationReadCookies();
            cookies.AuthCookie.ShouldNotBeNullOrWhiteSpace();
            cookies.LTDeviceId.ShouldNotBeNullOrWhiteSpace();
            cookies.LTDeviceId.ShouldBe( deviceId );
        }
        {
            // Calling without Token: the call is "Anonymous" but nothing must have changed.
            runningServer.Client.Token = null;
            using var message = await runningServer.Client.GetAsync( "echo/plop?userName" );
            var textMessage = await message.Content.ReadAsStringAsync();
            textMessage.ShouldBe( "/plop => ?userName (UserName: '')" );
            var cookies = runningServer.Client.AuthenticationReadCookies();
            cookies.AuthCookie.ShouldNotBeNullOrWhiteSpace();
            cookies.LTDeviceId.ShouldBe( deviceId );
        }
        string? token = null;
        {
            var refreshResponse = await runningServer.Client.AuthenticationRefreshAsync();
            Throw.DebugAssert( refreshResponse.Info != null );
            refreshResponse.Info.User.UserName.ShouldBe( "Albert" );
            token = refreshResponse.Token;
            var cookies = runningServer.Client.AuthenticationReadCookies();
            cookies.AuthCookie.ShouldNotBeNullOrWhiteSpace();
            cookies.LTDeviceId.ShouldNotBeNullOrWhiteSpace();
            cookies.LTDeviceId.ShouldBe( deviceId );
        }
        {
            // Calling with a Token.
            runningServer.Client.Token = token;
            using var message = await runningServer.Client.GetAsync( "echo/plop?userName" );
            var textMessage = await message.Content.ReadAsStringAsync();
            textMessage.ShouldBe( "/plop => ?userName (UserName: 'Albert')" );
            var cookies = runningServer.Client.AuthenticationReadCookies();
            cookies.AuthCookie.ShouldNotBeNullOrWhiteSpace();
            cookies.LTDeviceId.ShouldBe( deviceId );
        }
        {
            var refreshResponse = await runningServer.Client.AuthenticationRefreshAsync();
            Throw.DebugAssert( refreshResponse.Info != null );
            refreshResponse.Info.User.UserName.ShouldBe( "Albert" );
            var cookies = runningServer.Client.AuthenticationReadCookies();
            cookies.AuthCookie.ShouldNotBeNullOrWhiteSpace();
            cookies.LTDeviceId.ShouldNotBeNullOrWhiteSpace();
            cookies.LTDeviceId.ShouldBe( deviceId );
        }
    }

}
