using CK.Core;
using CK.Testing;
using FluentAssertions;
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
            textMessage.Should().Be( "/outside" );
            var cookies = runningServer.Client.AuthenticationReadCookies();
            cookies.AuthCookie.Should().BeNull();
            cookies.LTDeviceId.Should().BeNull();
            cookies.LTUserId.Should().BeNull();
        }
        {
            await runningServer.Client.AuthenticationRefreshAsync();
            var cookies = runningServer.Client.AuthenticationReadCookies();
            cookies.AuthCookie.Should().BeNull();
            cookies.LTDeviceId.Should().NotBeNullOrEmpty();
            deviceId = cookies.LTDeviceId;
        }
        {
            using var message = await runningServer.Client.GetAsync( "echo/hop" );
            var textMessage = await message.Content.ReadAsStringAsync();
            textMessage.Should().Be( "/hop" );
            var cookies = runningServer.Client.AuthenticationReadCookies();
            cookies.AuthCookie.Should().BeNull();
            cookies.LTDeviceId.Should().Be( deviceId );
        }
        {
            await runningServer.Client.AuthenticationRefreshAsync();
            var cookies = runningServer.Client.AuthenticationReadCookies();
            cookies.AuthCookie.Should().BeNull();
            cookies.LTDeviceId.Should().NotBeNullOrEmpty();
            cookies.LTDeviceId.Should().Be( deviceId );
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
            textMessage.Should().Be( "/none-yet" );
            var cookies = runningServer.Client.AuthenticationReadCookies();
            cookies.AuthCookie.Should().BeNull();
            cookies.LTDeviceId.Should().BeNull();
            cookies.LTUserId.Should().BeNull();
        }
        if( callRefreshFirst )
        {
            var refreshResponse = await runningServer.Client.AuthenticationRefreshAsync();
            Throw.DebugAssert( refreshResponse.Info != null );
            refreshResponse.Info.Level.Should().Be( CK.Auth.AuthLevel.None );
            var cookies = runningServer.Client.AuthenticationReadCookies();
            cookies.AuthCookie.Should().BeNull();
            cookies.LTDeviceId.Should().NotBeNullOrWhiteSpace();
            deviceId = cookies.LTDeviceId;
        }
        {
            await runningServer.Client.AuthenticationBasicLoginAsync( "Albert", expectSuccess: true, rememberMe: false );
            var cookies = runningServer.Client.AuthenticationReadCookies();
            cookies.AuthCookie.Should().NotBeNullOrWhiteSpace();
            cookies.LTDeviceId.Should().NotBeNullOrWhiteSpace();
            if( callRefreshFirst )
            {
                cookies.LTDeviceId.Should().Be( deviceId );
            }
            else deviceId = cookies.LTDeviceId;
        }
        {
            using var message = await runningServer.Client.GetAsync( "echo/hop" );
            var textMessage = await message.Content.ReadAsStringAsync();
            textMessage.Should().Be( "/hop" );
            var cookies = runningServer.Client.AuthenticationReadCookies();
            cookies.AuthCookie.Should().NotBeNullOrWhiteSpace();
            cookies.LTDeviceId.Should().Be( deviceId );
        }
        {
            var refreshResponse = await runningServer.Client.AuthenticationRefreshAsync();
            Throw.DebugAssert( refreshResponse.Info != null );
            refreshResponse.Info.User.UserName.Should().Be( "Albert" );
            var cookies = runningServer.Client.AuthenticationReadCookies();
            cookies.AuthCookie.Should().NotBeNullOrWhiteSpace();
            cookies.LTDeviceId.Should().NotBeNullOrWhiteSpace();
            cookies.LTDeviceId.Should().Be( deviceId );
        }
        {
            // Calling without Token: the call is "Anonymous" but nothing must have changed.
            runningServer.Client.Token = null;
            using var message = await runningServer.Client.GetAsync( "echo/plop?userName" );
            var textMessage = await message.Content.ReadAsStringAsync();
            textMessage.Should().Be( "/plop => ?userName (UserName: '')" );
            var cookies = runningServer.Client.AuthenticationReadCookies();
            cookies.AuthCookie.Should().NotBeNullOrWhiteSpace();
            cookies.LTDeviceId.Should().Be( deviceId );
        }
        string? token = null;
        {
            var refreshResponse = await runningServer.Client.AuthenticationRefreshAsync();
            Throw.DebugAssert( refreshResponse.Info != null );
            refreshResponse.Info.User.UserName.Should().Be( "Albert" );
            token = refreshResponse.Token;
            var cookies = runningServer.Client.AuthenticationReadCookies();
            cookies.AuthCookie.Should().NotBeNullOrWhiteSpace();
            cookies.LTDeviceId.Should().NotBeNullOrWhiteSpace();
            cookies.LTDeviceId.Should().Be( deviceId );
        }
        {
            // Calling with a Token.
            runningServer.Client.Token = token;
            using var message = await runningServer.Client.GetAsync( "echo/plop?userName" );
            var textMessage = await message.Content.ReadAsStringAsync();
            textMessage.Should().Be( "/plop => ?userName (UserName: 'Albert')" );
            var cookies = runningServer.Client.AuthenticationReadCookies();
            cookies.AuthCookie.Should().NotBeNullOrWhiteSpace();
            cookies.LTDeviceId.Should().Be( deviceId );
        }
        {
            var refreshResponse = await runningServer.Client.AuthenticationRefreshAsync();
            Throw.DebugAssert( refreshResponse.Info != null );
            refreshResponse.Info.User.UserName.Should().Be( "Albert" );
            var cookies = runningServer.Client.AuthenticationReadCookies();
            cookies.AuthCookie.Should().NotBeNullOrWhiteSpace();
            cookies.LTDeviceId.Should().NotBeNullOrWhiteSpace();
            cookies.LTDeviceId.Should().Be( deviceId );
        }
    }

}
