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
    public class DeviceIdTests
    {
        [Test]
        public async Task DeviceId_is_not_set_until_wefront_call_and_is_not_changed_Async()
        {
            using( var s = new AuthServer() )
            {
                string? deviceId = null;
                {
                    using var message = await s.Client.Get( "echo/outside" );
                    var textMessage = await message.Content.ReadAsStringAsync();
                    textMessage.Should().Be( "/outside" );
                    var cookies = s.ReadClientCookies();
                    cookies.AuthCookie.Should().BeNull();
                    cookies.LTDeviceId.Should().BeNull();
                    cookies.LTUserId.Should().BeNull();
                }
                {
                    await s.CallRefreshEndPointAsync();
                    var cookies = s.ReadClientCookies();
                    cookies.AuthCookie.Should().BeNull();
                    cookies.LTDeviceId.Should().NotBeNullOrEmpty();
                    deviceId = cookies.LTDeviceId;
                }
                {
                    using var message = await s.Client.Get( "echo/hop" );
                    var textMessage = await message.Content.ReadAsStringAsync();
                    textMessage.Should().Be( "/hop" );
                    var cookies = s.ReadClientCookies();
                    cookies.AuthCookie.Should().BeNull();
                    cookies.LTDeviceId.Should().Be( deviceId );
                }
                {
                    await s.CallRefreshEndPointAsync();
                    var cookies = s.ReadClientCookies();
                    cookies.AuthCookie.Should().BeNull();
                    cookies.LTDeviceId.Should().NotBeNullOrEmpty();
                    cookies.LTDeviceId.Should().Be( deviceId );
                }
            }
        }

        [TestCase( true )]
        [TestCase( false )]
        public async Task DeviceId_is_independent_of_the_authentication_Async( bool callRefreshFirst )
        {
            using( var s = new AuthServer() )
            {
                string? deviceId = null;
                {
                    using var message = await s.Client.Get( "echo/none-yet" );
                    var textMessage = await message.Content.ReadAsStringAsync();
                    textMessage.Should().Be( "/none-yet" );
                    var cookies = s.ReadClientCookies();
                    cookies.AuthCookie.Should().BeNull();
                    cookies.LTDeviceId.Should().BeNull();
                    cookies.LTUserId.Should().BeNull();
                }
                if( callRefreshFirst )
                {
                    var refreshResponse = await s.CallRefreshEndPointAsync();
                    refreshResponse.Info.Level.Should().Be( CK.Auth.AuthLevel.None );
                    var cookies = s.ReadClientCookies();
                    cookies.AuthCookie.Should().BeNull();
                    cookies.LTDeviceId.Should().NotBeNullOrWhiteSpace();
                    deviceId = cookies.LTDeviceId;
                }
                {
                    await s.LoginAlbertViaBasicProviderAsync( rememberMe: false );
                    var cookies = s.ReadClientCookies();
                    cookies.AuthCookie.Should().NotBeNullOrWhiteSpace();
                    cookies.LTDeviceId.Should().NotBeNullOrWhiteSpace();
                    if( callRefreshFirst )
                    {
                        cookies.LTDeviceId.Should().Be( deviceId );
                    }
                    else deviceId = cookies.LTDeviceId;
                }
                {
                    using var message = await s.Client.Get( "echo/hop" );
                    var textMessage = await message.Content.ReadAsStringAsync();
                    textMessage.Should().Be( "/hop" );
                    var cookies = s.ReadClientCookies();
                    cookies.AuthCookie.Should().NotBeNullOrWhiteSpace();
                    cookies.LTDeviceId.Should().Be( deviceId );
                }
                {
                    var refreshResponse = await s.CallRefreshEndPointAsync();
                    refreshResponse.Info.User.UserName.Should().Be( "Albert" );
                    var cookies = s.ReadClientCookies();
                    cookies.AuthCookie.Should().NotBeNullOrWhiteSpace();
                    cookies.LTDeviceId.Should().NotBeNullOrWhiteSpace();
                    cookies.LTDeviceId.Should().Be( deviceId );
                }
                {
                    // Calling without Token: the call is "Anonymous" but nothing must have changed.
                    using var message = await s.Client.Get( "echo/plop?userName" );
                    var textMessage = await message.Content.ReadAsStringAsync();
                    textMessage.Should().Be( "/plop => ?userName (UserName: '')" );
                    var cookies = s.ReadClientCookies();
                    cookies.AuthCookie.Should().NotBeNullOrWhiteSpace();
                    cookies.LTDeviceId.Should().Be( deviceId );
                }
                string? token = null;
                {
                    var refreshResponse = await s.CallRefreshEndPointAsync();
                    refreshResponse.Info.User.UserName.Should().Be( "Albert" );
                    token = refreshResponse.Token;
                    var cookies = s.ReadClientCookies();
                    cookies.AuthCookie.Should().NotBeNullOrWhiteSpace();
                    cookies.LTDeviceId.Should().NotBeNullOrWhiteSpace();
                    cookies.LTDeviceId.Should().Be( deviceId );
                }
                {
                    // Calling with a Token.
                    s.Client.Token = token;
                    using var message = await s.Client.Get( "echo/plop?userName" );
                    var textMessage = await message.Content.ReadAsStringAsync();
                    textMessage.Should().Be( "/plop => ?userName (UserName: 'Albert')" );
                    var cookies = s.ReadClientCookies();
                    cookies.AuthCookie.Should().NotBeNullOrWhiteSpace();
                    cookies.LTDeviceId.Should().Be( deviceId );
                }
                {
                    var refreshResponse = await s.CallRefreshEndPointAsync();
                    refreshResponse.Info.User.UserName.Should().Be( "Albert" );
                    var cookies = s.ReadClientCookies();
                    cookies.AuthCookie.Should().NotBeNullOrWhiteSpace();
                    cookies.LTDeviceId.Should().NotBeNullOrWhiteSpace();
                    cookies.LTDeviceId.Should().Be( deviceId );
                }
            }
        }

    }
}
