using CK.AspNet.Auth;
using CK.Auth;
using CK.Core;
using CK.DB.Actor;
using CK.DB.Auth;
using CK.SqlServer;
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
        const string basicLoginUri = "/.webfront/c/basicLogin";
        const string unsafeDirectLoginUri = "/.webfront/c/unsafeDirectLogin";
        const string refreshUri = "/.webfront/c/refresh";
        const string logoutUri = "/.webfront/c/logout";
        const string tokenExplainUri = "/.webfront/token";

        [TestCase( true )]
        [TestCase( false )]
        public async Task basic_authentication_via_generic_wrapper_on_a_created_user_Async( bool allowed )
        {
            var user = TestHelper.AutomaticServices.GetRequiredService<UserTable>();
            var auth = TestHelper.AutomaticServices.GetRequiredService<IAuthenticationDatabaseService>();
            var basic = auth.FindRequiredProvider( "Basic", mustHavePayload: false );

            using( DirectLoginAllower.Allow( allowed ? DirectLoginAllower.What.BasicOnly : DirectLoginAllower.What.None ) )
            using( var ctx = new SqlStandardCallContext( TestHelper.Monitor ) )
            using( var server = new AuthServer() )
            {
                string userName = Guid.NewGuid().ToString();
                int idUser = await user.CreateUserAsync( ctx, 1, userName );
                basic.CreateOrUpdateUser( ctx, 1, idUser, "pass" );

                string? deviceId = null;
                {
                    var payload = new JObject( new JProperty( "userName", userName ), new JProperty( "password", "pass" ) );
                    var param = new JObject( new JProperty( "provider", "Basic" ), new JProperty( "payload", payload ) );
                    HttpResponseMessage authBasic = await server.Client.PostJSONAsync( unsafeDirectLoginUri, param.ToString() );
                    if( allowed )
                    {
                        authBasic.EnsureSuccessStatusCode();
                        var c = AuthResponse.Parse( server.TypeSystem, await authBasic.Content.ReadAsStringAsync() );
                        Throw.DebugAssert( c.Info != null );
                        c.Info.Level.Should().Be( AuthLevel.Normal );
                        c.Info.User.UserId.Should().Be( idUser );
                        c.Info.User.Schemes.Select( p => p.Name ).Should().BeEquivalentTo( new[] { "Basic" } );
                        c.Token.Should().NotBeNullOrWhiteSpace();
                        deviceId = c.Info.DeviceId;
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
                    HttpResponseMessage authFailed = await server.Client.PostJSONAsync( unsafeDirectLoginUri, param.ToString() );
                    authFailed.StatusCode.Should().Be( HttpStatusCode.Unauthorized );
                    var c = AuthResponse.Parse( server.TypeSystem, await authFailed.Content.ReadAsStringAsync() );
                    ShouldBeUnsafeUser( c, idUser, deviceId! );
                }
            }
        }

        [TestCase( "Albert", "pass" )]
        [TestCase( "Paula", "pass" )]
        public async Task basic_authentication_on_user_Async( string userName, string password )
        {
            var user = SharedEngine.Map.StObjs.Obtain<UserTable>();
            var basic = SharedEngine.Map.StObjs.Obtain<IBasicAuthenticationProvider>();
            Throw.DebugAssert( user != null && basic != null );
            using( var ctx = new SqlStandardCallContext( TestHelper.Monitor ) )
            using( var server = new AuthServer() )
            {
                int idUser = await user.CreateUserAsync( ctx, 1, userName );
                if( idUser == -1 ) idUser = await user.FindByNameAsync( ctx, userName );
                await basic.CreateOrUpdatePasswordUserAsync( ctx, 1, idUser, password );

                string deviceId;
                {
                    var payload = new JObject(
                                        new JProperty( "userName", userName ),
                                        new JProperty( "password", password ) );
                    HttpResponseMessage authBasic = await server.Client.PostJSONAsync( basicLoginUri, payload.ToString() );
                    var c = AuthResponse.Parse( server.TypeSystem, await authBasic.Content.ReadAsStringAsync() );
                    Throw.DebugAssert( c.Info != null );
                    deviceId = c.Info.DeviceId;
                    deviceId.Should().NotBeNullOrWhiteSpace();
                    c.Info.Level.Should().Be( AuthLevel.Normal );
                    c.Info.User.UserId.Should().Be( idUser );
                    c.Info.User.Schemes.Select( p => p.Name ).Should().BeEquivalentTo( new[] { "Basic" } );
                    c.Token.Should().NotBeNullOrWhiteSpace();
                }

                {
                    var payload = new JObject(
                                        new JProperty( "userName", userName ),
                                        new JProperty( "password", "failed" + password ) );
                    HttpResponseMessage authFailed = await server.Client.PostJSONAsync( basicLoginUri, payload.ToString() );
                    var c = AuthResponse.Parse( server.TypeSystem, await authFailed.Content.ReadAsStringAsync() );
                    ShouldBeUnsafeUser( c, idUser, deviceId );
                }
            }
        }

        static void ShouldBeUnsafeUser( AuthResponse c, int idUser, string deviceId )
        {
            Throw.DebugAssert( c.Info != null );
            c.Info.Level.Should().Be( AuthLevel.Unsafe );
            c.Info.User.UserId.Should().Be( 0 );
            c.Info.ActualUser.UserId.Should().Be( 0 );
            c.Info.UnsafeUser.UserId.Should().Be( idUser );
            c.Token.Should().NotBeNullOrWhiteSpace();
            c.Info.DeviceId.Should().Be( deviceId );
        }

        [Test]
        public async Task unsafe_direct_login_returns_BadRequest_and_JSON_ArgumentException_when_payload_is_not_in_the_expected_format_Async()
        {
            using( DirectLoginAllower.Allow( DirectLoginAllower.What.All ) )
            using( var server = new AuthServer() )
            {
                // Missing userName or userId.
                {
                    var param = new JObject( new JProperty( "provider", "Basic" ),
                                             new JProperty( "payload",
                                                    new JObject( new JProperty( "password", "pass" ) ) ) );
                    HttpResponseMessage m = await server.Client.PostJSONAsync( unsafeDirectLoginUri, param.ToString() );
                    m.StatusCode.Should().Be( HttpStatusCode.BadRequest );
                    AuthResponse r = AuthResponse.Parse( server.TypeSystem, await m.Content.ReadAsStringAsync() );
                    r.ErrorId.Should().Be( "System.ArgumentException" );
                    r.ErrorText.Should().Contain( "Invalid payload. Missing 'UserId' -> int or 'UserName' -> string" );
                }
                // Missing password.
                {
                    var param = new JObject( new JProperty( "provider", "Basic" ),
                                             new JProperty( "payload",
                                                    new JObject( new JProperty( "userId", "3712" ) ) ) );
                    HttpResponseMessage m = await server.Client.PostJSONAsync( unsafeDirectLoginUri, param.ToString() );
                    m.StatusCode.Should().Be( HttpStatusCode.BadRequest );
                    AuthResponse r = AuthResponse.Parse( server.TypeSystem, await m.Content.ReadAsStringAsync() );
                    r.ErrorId.Should().Be( "System.ArgumentException" );
                    r.ErrorText.Should().Contain( "Invalid payload. Missing 'Password' -> string entry." );
                }
                // Totally invalid payload.
                {
                    var param = new JObject( new JProperty( "provider", "Basic" ),
                                             new JProperty( "payload", null! ) );
                    HttpResponseMessage m = await server.Client.PostJSONAsync( unsafeDirectLoginUri, param.ToString() );
                    m.StatusCode.Should().Be( HttpStatusCode.BadRequest );
                    AuthResponse r = AuthResponse.Parse( server.TypeSystem, await m.Content.ReadAsStringAsync() );
                    r.ErrorId.Should().Be( "System.ArgumentException" );
                    r.ErrorText.Should().Contain( "Invalid payload. It must be either a Tuple or ValueTuple (int,string) or (string,string) or a IDictionary<string,object?> or IEnumerable<KeyValuePair<string,object?>> or IEnumerable<(string,object?)> with 'Password' -> string and 'UserId' -> int or 'UserName' -> string entries." );
                }
            }
        }

        [TestCase( "Albert", "pass", true )]
        [TestCase( "Paula", "pass", false )]
        public async Task IWebFrontAuthValidateLoginService_can_prevent_unsafe_direct_login_Async( string userName, string password, bool okInEvil )
        {
            var user = SharedEngine.Map.StObjs.Obtain<UserTable>();
            var basic = SharedEngine.Map.StObjs.Obtain<IBasicAuthenticationProvider>();
            Throw.DebugAssert( user != null && basic != null );
            using( DirectLoginAllower.Allow( DirectLoginAllower.What.All ) )
            using( var ctx = new SqlStandardCallContext() )
            using( var server = new AuthServer() )
            {
                await ctx[user].Connection.EnsureOpenAsync();
                int idUser = await user.CreateUserAsync( ctx, 1, userName );
                if( idUser == -1 ) idUser = await user.FindByNameAsync( ctx, userName );
                await basic.CreateOrUpdatePasswordUserAsync( ctx, 1, idUser, password );

                string deviceId;
                {
                    var param = new JObject(
                                        new JProperty( "provider", "Basic" ),
                                        new JProperty( "payload", new JObject(
                                            new JProperty( "userName", userName ),
                                            new JProperty( "password", password ) ) ),
                                        new JProperty( "userData", new JObject(
                                                new JProperty( "zone", "good" ) ) ) );
                    HttpResponseMessage authBasic = await server.Client.PostJSONAsync( unsafeDirectLoginUri, param.ToString() );
                    var c = AuthResponse.Parse( server.TypeSystem, await authBasic.Content.ReadAsStringAsync() );
                    Throw.DebugAssert( c.Info != null );
                    deviceId = c.Info.DeviceId;
                    deviceId.Should().NotBeNullOrWhiteSpace();
                    c.Info.Level.Should().Be( AuthLevel.Normal );
                    c.Info.User.UserId.Should().Be( idUser );
                    c.Info.User.Schemes.Select( p => p.Name ).Should().BeEquivalentTo( new[] { "Basic" } );
                    c.Token.Should().NotBeNullOrWhiteSpace();
                    c.UserData.Should().Contain( new[] { new KeyValuePair<string, string>( "zone", "good" ) } );
                }

                {
                    var param = new JObject(
                                        new JProperty( "provider", "Basic" ),
                                        new JProperty( "payload", new JObject(
                                            new JProperty( "userName", userName ),
                                            new JProperty( "password", password ) ) ),
                                        new JProperty( "userData",
                                            new JObject( new JProperty( "zone", "<&>vil" ) ) ) );
                    HttpResponseMessage auth = await server.Client.PostJSONAsync( unsafeDirectLoginUri, param.ToString() );
                    var c = AuthResponse.Parse( server.TypeSystem, await auth.Content.ReadAsStringAsync() );
                    if( okInEvil )
                    {
                        Throw.DebugAssert( c.Info != null );
                        c.Info.Level.Should().Be( AuthLevel.Normal );
                        c.Info.User.UserId.Should().Be( idUser );
                        c.Info.User.Schemes.Select( p => p.Name ).Should().BeEquivalentTo( new[] { "Basic" } );
                        c.Token.Should().NotBeNullOrWhiteSpace();
                        c.ErrorId.Should().BeNull();
                        c.ErrorText.Should().BeNull();
                        c.UserData.Should().Contain( new[] { new KeyValuePair<string, string>( "zone", "<&>vil" ) } );
                    }
                    else
                    {
                        ShouldBeUnsafeUser( c, idUser, deviceId );
                        c.ErrorId.Should().Be( "Validation" );
                        c.ErrorText.Should().Be( "Paula must not go in the <&>vil Zone!" );
                        c.UserData.Should().Contain( new[] { new KeyValuePair<string, string>( "zone", "<&>vil" ) } );
                    }
                }
            }
        }

        [TestCase( "Albert", "pass", true )]
        [TestCase( "Paula", "pass", false )]
        public async Task IWebFrontAuthValidateLoginService_can_prevent_basic_login_Async( string userName, string password, bool okInEvil )
        {
            var user = SharedEngine.Map.StObjs.Obtain<UserTable>();
            var basic = SharedEngine.Map.StObjs.Obtain<IBasicAuthenticationProvider>();
            Throw.DebugAssert( user != null && basic != null );
            using( var ctx = new SqlStandardCallContext() )
            using( var server = new AuthServer() )
            {
                await ctx[user].Connection.EnsureOpenAsync();
                int idUser = await user.CreateUserAsync( ctx, 1, userName );
                if( idUser == -1 ) idUser = await user.FindByNameAsync( ctx, userName );
                await basic.CreateOrUpdatePasswordUserAsync( ctx, 1, idUser, password );

                string deviceId;
                {
                    // Zone is "good".
                    var payload = new JObject(
                                        new JProperty( "userName", userName ),
                                        new JProperty( "password", password ),
                                        new JProperty( "userData", new JObject(
                                                new JProperty( "zone", "good" ) ) ) );
                    HttpResponseMessage authBasic = await server.Client.PostJSONAsync( basicLoginUri, payload.ToString() );
                    var c = AuthResponse.Parse( server.TypeSystem, await authBasic.Content.ReadAsStringAsync() );
                        Throw.DebugAssert( c.Info != null );
                    deviceId = c.Info.DeviceId;
                    c.Info.Level.Should().Be( AuthLevel.Normal );
                    c.Info.User.UserId.Should().Be( idUser );
                    c.Info.User.Schemes.Select( p => p.Name ).Should().BeEquivalentTo( new[] { "Basic" } );
                    c.Token.Should().NotBeNullOrWhiteSpace();
                    c.UserData.Should().Contain( new[] { new KeyValuePair<string, string>( "zone", "good" ) } );
                }

                {
                    // Zone is "<&>vil".
                    var payload = new JObject(
                                        new JProperty( "userName", userName ),
                                        new JProperty( "password", password ),
                                        new JProperty( "userData", new JObject(
                                                new JProperty( "zone", "<&>vil" ) ) ) );
                    HttpResponseMessage auth = await server.Client.PostJSONAsync( basicLoginUri, payload.ToString() );
                    var c = AuthResponse.Parse( server.TypeSystem, await auth.Content.ReadAsStringAsync() );
                    if( okInEvil ) // When userName is "Albert".
                    {
                        Throw.DebugAssert( c.Info != null );
                        c.Info.Level.Should().Be( AuthLevel.Normal );
                        c.Info.User.UserId.Should().Be( idUser );
                        c.Info.User.Schemes.Select( p => p.Name ).Should().BeEquivalentTo( new[] { "Basic" } );
                        c.Token.Should().NotBeNullOrWhiteSpace();
                        c.ErrorId.Should().BeNull();
                        c.ErrorText.Should().BeNull();
                        c.UserData.Should().Contain( new[] { new KeyValuePair<string, string>( "zone", "<&>vil" ) } );
                    }
                    else  // When userName is "Paula".
                    {
                        ShouldBeUnsafeUser( c, idUser, deviceId );
                        c.ErrorId.Should().Be( "Validation" );
                        c.ErrorText.Should().Be( "Paula must not go in the <&>vil Zone!" );
                        c.UserData.Should().Contain( new[] { new KeyValuePair<string, string>( "zone", "<&>vil" ) } );
                    }
                }
            }
        }

    }

}
