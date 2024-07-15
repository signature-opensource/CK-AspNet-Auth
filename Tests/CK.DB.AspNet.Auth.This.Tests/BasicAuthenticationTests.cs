using CK.AspNet.Auth;
using CK.Auth;
using CK.Core;
using CK.DB.Actor;
using CK.DB.Auth;
using CK.SqlServer;
using CK.Testing;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Newtonsoft.Json.Linq;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.DB.AspNet.Auth.Tests
{
    [TestFixture]
    public partial class BasicAuthenticationTests
    {
        [TestCase( true )]
        [TestCase( false )]
        public async Task basic_authentication_via_generic_wrapper_on_a_created_user_Async( bool allowed )
        {
            using var allowConfigure = DirectLoginAllower.SetAllow( allowed ? DirectLoginAllower.What.BasicOnly : DirectLoginAllower.What.None );

            await using var runningServer = await SharedEngine.Map.CreateAspNetAuthServerAsync();

            var user = runningServer.Services.GetRequiredService<UserTable>();
            var auth = runningServer.Services.GetRequiredService<IAuthenticationDatabaseService>();
            var basic = auth.FindRequiredProvider( "Basic", mustHavePayload: false );

            using var ctx = new SqlStandardCallContext( TestHelper.Monitor );

            string userName = Guid.NewGuid().ToString();
            int idUser = await user.CreateUserAsync( ctx, 1, userName );
            basic.CreateOrUpdateUser( ctx, 1, idUser, "pass" );

            string? deviceId = null;
            {
                var payload = new JObject( new JProperty( "userName", userName ), new JProperty( "password", "pass" ) );
                var param = new JObject( new JProperty( "provider", "Basic" ), new JProperty( "payload", payload ) );
                using HttpResponseMessage authBasic = await runningServer.Client.PostJsonAsync( RunningAspNetAuthServerExtensions.UnsafeDirectLoginUri, param.ToString() );
                if( allowed )
                {
                    authBasic.EnsureSuccessStatusCode();
                    var r = AuthServerResponse.Parse( runningServer.GetAuthenticationTypeSystem(), await authBasic.Content.ReadAsStringAsync() );
                    Throw.DebugAssert( r.Info != null );
                    r.Info.Level.Should().Be( AuthLevel.Normal );
                    r.Info.User.UserId.Should().Be( idUser );
                    r.Info.User.Schemes.Select( p => p.Name ).Should().BeEquivalentTo( new[] { "Basic" } );
                    r.Token.Should().NotBeNullOrWhiteSpace();
                    deviceId = r.Info.DeviceId;
                    Throw.DebugAssert( deviceId != null );
                }
                else
                {
                    authBasic.StatusCode.Should().Be( HttpStatusCode.Forbidden );
                }
            }
            if( allowed )
            {
                var payload = new JObject( new JProperty( "userName", userName ), new JProperty( "password", "failed" ) );
                var param = new JObject( new JProperty( "provider", "Basic" ), new JProperty( "payload", payload ) );
                using HttpResponseMessage authFailed = await runningServer.Client.PostJsonAsync( RunningAspNetAuthServerExtensions.UnsafeDirectLoginUri, param.ToString() );
                authFailed.StatusCode.Should().Be( HttpStatusCode.Unauthorized );
                var r = AuthServerResponse.Parse( runningServer.GetAuthenticationTypeSystem(), await authFailed.Content.ReadAsStringAsync() );
                ShouldBeUnsafeUser( r, idUser, deviceId! );
            }
        }

        [TestCase( "Albert", "pass" )]
        [TestCase( "Paula", "pass" )]
        public async Task basic_authentication_on_user_Async( string userName, string password )
        {
            await using var runningServer = await SharedEngine.Map.CreateAspNetAuthServerAsync();

            var user = runningServer.Services.GetRequiredService<UserTable>();
            var basic = runningServer.Services.GetRequiredService<IBasicAuthenticationProvider>();

            using var ctx = new SqlStandardCallContext( TestHelper.Monitor );

            int idUser = await user.CreateUserAsync( ctx, 1, userName );
            if( idUser == -1 ) idUser = await user.FindByNameAsync( ctx, userName );
            await basic.CreateOrUpdatePasswordUserAsync( ctx, 1, idUser, password );

            string deviceId;
            {
                var r = await runningServer.Client.LoginViaBasicProviderAsync( userName, true, password: password );
                Throw.DebugAssert( r.Info != null );
                deviceId = r.Info.DeviceId;
                deviceId.Should().NotBeNullOrWhiteSpace();
            }
            {
                var rFailed = await runningServer.Client.LoginViaBasicProviderAsync( userName, true, password: "failed" + password );
                ShouldBeUnsafeUser( rFailed, idUser, deviceId );
            }
        }

        static void ShouldBeUnsafeUser( AuthServerResponse r, int idUser, string deviceId )
        {
            Throw.DebugAssert( r.Info != null );
            r.Info.Level.Should().Be( AuthLevel.Unsafe );
            r.Info.User.UserId.Should().Be( 0 );
            r.Info.ActualUser.UserId.Should().Be( 0 );
            r.Info.UnsafeUser.UserId.Should().Be( idUser );
            r.Token.Should().NotBeNullOrWhiteSpace();
            r.Info.DeviceId.Should().Be( deviceId );
        }

        [Test]
        public async Task unsafe_direct_login_returns_BadRequest_and_JSON_ArgumentException_when_payload_is_not_in_the_expected_format_Async()
        {
            using var allowConfigure = DirectLoginAllower.SetAllow( DirectLoginAllower.What.All );

            await using var runningServer = await SharedEngine.Map.CreateAspNetAuthServerAsync();

            // Missing userName or userId.
            {
                var param = new JObject( new JProperty( "provider", "Basic" ),
                                            new JProperty( "payload",
                                                new JObject( new JProperty( "password", "pass" ) ) ) );
                using HttpResponseMessage m = await runningServer.Client.PostJsonAsync( RunningAspNetAuthServerExtensions.UnsafeDirectLoginUri, param.ToString() );
                m.StatusCode.Should().Be( HttpStatusCode.BadRequest );
                var r = AuthServerResponse.Parse( runningServer.GetAuthenticationTypeSystem(), await m.Content.ReadAsStringAsync() );
                r.ErrorId.Should().Be( "System.ArgumentException" );
                r.ErrorText.Should().Be( "Invalid payload. Missing 'UserId' -> int or 'UserName' -> string" );
            }
            // Missing password.
            {
                var param = new JObject( new JProperty( "provider", "Basic" ),
                                            new JProperty( "payload",
                                                new JObject( new JProperty( "userId", "3712" ) ) ) );
                using HttpResponseMessage m = await runningServer.Client.PostJsonAsync( RunningAspNetAuthServerExtensions.UnsafeDirectLoginUri, param.ToString() );
                m.StatusCode.Should().Be( HttpStatusCode.BadRequest );
                var r = AuthServerResponse.Parse( runningServer.GetAuthenticationTypeSystem(), await m.Content.ReadAsStringAsync() );
                r.ErrorId.Should().Be( "System.ArgumentException" );
                r.ErrorText.Should().Be( "Invalid payload. Invalid payload. Missing 'Password' -> string entry." );
            }
            // Totally invalid payload.
            {
                var param = new JObject( new JProperty( "provider", "Basic" ),
                                            new JProperty( "payload",
                                                new JObject( new JProperty( "userId", "3712" ) ) ) );
                using HttpResponseMessage m = await runningServer.Client.PostJsonAsync( RunningAspNetAuthServerExtensions.UnsafeDirectLoginUri, param.ToString() );
                m.StatusCode.Should().Be( HttpStatusCode.BadRequest );
                var r = AuthServerResponse.Parse( runningServer.GetAuthenticationTypeSystem(), await m.Content.ReadAsStringAsync() );
                r.ErrorId.Should().Be( "System.ArgumentException" );
                r.ErrorText.Should().Be( "Invalid payload. It must be either a Tuple or ValueTuple (int,string) or (string,string) or a IDictionary<string,object?> or IEnumerable<KeyValuePair<string,object?>> or IEnumerable<(string,object?)> with 'Password' -> string and 'UserId' -> int or 'UserName' -> string entries." );
            }
        }

        [TestCase( "Albert", "pass", true )]
        [TestCase( "Paula", "pass", false )]
        public async Task IWebFrontAuthValidateLoginService_can_prevent_unsafe_direct_login_Async( string userName, string password, bool okInEvil )
        {
            using var allowConfigure = DirectLoginAllower.SetAllow( DirectLoginAllower.What.All );

            await using var runningServer = await SharedEngine.Map.CreateAspNetAuthServerAsync();

            var user = runningServer.Services.GetRequiredService<UserTable>();
            var basic = runningServer.Services.GetRequiredService<IBasicAuthenticationProvider>();

            using var ctx = new SqlStandardCallContext();

            await ctx[user].Connection.EnsureOpenAsync();
            int idUser = await user.CreateUserAsync( ctx, 1, userName );
            if( idUser == -1 ) idUser = await user.FindByNameAsync( ctx, userName );
            await basic.CreateOrUpdatePasswordUserAsync( ctx, 1, idUser, password );

            string deviceId;
            {
                var r = await runningServer.Client.LoginViaBasicProviderAsync( userName, true, useGenericWrapper: true, password: password, jsonUserData: """{"zone":"good"}""" );
                Throw.DebugAssert( r.Info != null );
                deviceId = r.Info.DeviceId;
                deviceId.Should().NotBeNullOrWhiteSpace();
                r.UserData.Should().Contain( [("zone", "good")] );
            }

            {
                var r = await runningServer.Client.LoginViaBasicProviderAsync( userName, true, useGenericWrapper: true, password: password, jsonUserData: """{"zone":"<&>vil"}""" );
                Throw.DebugAssert( r.Info != null );
                if( okInEvil )
                {
                    Throw.DebugAssert( r.Info != null );
                    r.Info.Level.Should().Be( AuthLevel.Normal );
                    r.Info.User.UserId.Should().Be( idUser );
                    r.Info.User.Schemes.Select( p => p.Name ).Should().BeEquivalentTo( ["Basic"] );
                    r.Token.Should().NotBeNullOrWhiteSpace();
                    r.UserData.Should().Contain( [( "zone", "<&>vil" )] );
                }
                else
                {
                    ShouldBeUnsafeUser( r, idUser, deviceId );
                    r.ErrorId.Should().Be( "Validation" );
                    r.ErrorText.Should().Be( "Paula must not go in the <&>vil Zone!" );
                    r.UserData.Should().Contain( [("zone", "<&>vil")] );
                }
            }
        }

        [TestCase( "Albert", "pass", true )]
        [TestCase( "Paula", "pass", false )]
        public async Task IWebFrontAuthValidateLoginService_can_prevent_basic_login_Async( string userName, string password, bool okInEvil )
        {
            await using var runningServer = await SharedEngine.Map.CreateAspNetAuthServerAsync();

            var user = runningServer.Services.GetRequiredService<UserTable>();
            var basic = runningServer.Services.GetRequiredService<IBasicAuthenticationProvider>();

            using var ctx = new SqlStandardCallContext( TestHelper.Monitor );

            await ctx[user].Connection.EnsureOpenAsync();
            int idUser = await user.CreateUserAsync( ctx, 1, userName );
            if( idUser == -1 ) idUser = await user.FindByNameAsync( ctx, userName );
            await basic.CreateOrUpdatePasswordUserAsync( ctx, 1, idUser, password );

            string deviceId;
            {
                // Zone is "good".
                var r = await runningServer.Client.LoginViaBasicProviderAsync( userName, true, password: password, jsonUserData: """{"zone":"good"}""" );
                Throw.DebugAssert( r.Info != null );
                deviceId = r.Info.DeviceId;
                r.Info.Level.Should().Be( AuthLevel.Normal );
                r.Info.User.UserId.Should().Be( idUser );
                r.Info.User.Schemes.Select( p => p.Name ).Should().BeEquivalentTo( ["Basic"] );
                r.Token.Should().NotBeNullOrWhiteSpace();
                r.UserData.Should().Contain( [("zone", "good")] );
            }
            {
                // Zone is "<&>vil".
                var r = await runningServer.Client.LoginViaBasicProviderAsync( userName, true, password: password, jsonUserData: """{"zone":"<&>vil"}""" );
                if( okInEvil ) // When userName is "Albert".
                {
                    Throw.DebugAssert( r.Info != null );
                    r.Info.Level.Should().Be( AuthLevel.Normal );
                    r.Info.User.UserId.Should().Be( idUser );
                    r.Info.User.Schemes.Select( p => p.Name ).Should().BeEquivalentTo( ["Basic"] );
                    r.Token.Should().NotBeNullOrWhiteSpace();
                    r.ErrorId.Should().BeNull();
                    r.ErrorText.Should().BeNull();
                    r.UserData.Should().Contain( [("zone", "<&>vil")] );
                }
                else  // When userName is "Paula".
                {
                    ShouldBeUnsafeUser( r, idUser, deviceId );
                    r.ErrorId.Should().Be( "Validation" );
                    r.ErrorText.Should().Be( "Paula must not go in the <&>vil Zone!" );
                    r.UserData.Should().Contain( [("zone", "<&>vil")] );
                }
            }
        }

    }

}
