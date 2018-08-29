using CK.AspNet.Auth;
using CK.Auth;
using CK.Core;
using CK.DB.Actor;
using CK.DB.Auth;
using CK.SqlServer;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Newtonsoft.Json.Linq;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using static CK.Testing.DBSetupTestHelper;

namespace CK.DB.AspNet.Auth.Tests
{
    [TestFixture]
    public class BasicAuthenticationTests
    {
        const string basicLoginUri = "/.webfront/c/basicLogin";
        const string unsafeDirectLoginUri = "/.webfront/c/unsafeDirectLogin";
        const string refreshUri = "/.webfront/c/refresh";
        const string logoutUri = "/.webfront/c/logout";
        const string tokenExplainUri = "/.webfront/token";

        class RefreshResponse
        {
            public IAuthenticationInfo Info { get; set; }

            public string Token { get; set; }

            public bool Refreshable { get; set; }

            public IList<KeyValuePair<string, string>> UserData { get; } = new List<KeyValuePair<string, string>>();

            public string ErrorId { get; set; }

            public string ErrorText { get; set; }

            public static RefreshResponse Parse( IAuthenticationTypeSystem t, string json )
            {
                JObject o = JObject.Parse( json );
                var r = new RefreshResponse();
                if( o["info"].Type == JTokenType.Object )
                {
                    r.Info = t.AuthenticationInfo.FromJObject( (JObject)o["info"] );
                }
                r.Token = (string)o["token"];
                r.Refreshable = (bool)o["refreshable"];
                JObject userData = (JObject)o["userData"];
                if( userData != null )
                {
                    foreach( var kv in userData )
                    {
                        r.UserData.Add( new KeyValuePair<string, string>( kv.Key, (string)kv.Value ) );
                    }
                }
                r.ErrorId = (string)o["errorId"];
                r.ErrorText = (string)o["errorText"];
                return r;
            }
        }

        [TestCase( true )]
        [TestCase( false )]
        public async Task basic_authentication_via_generic_wrapper_on_a_created_user( bool allowed )
        {
            var user = TestHelper.StObjMap.StObjs.Obtain<UserTable>();
            var auth = TestHelper.StObjMap.StObjs.Obtain<IAuthenticationDatabaseService>();
            var basic = auth.FindProvider( "Basic" );
   
            using( var ctx = new SqlStandardCallContext() )
            using( var server = new AuthServer( options: null, configureServices: services =>
            {
                if( allowed )
                {
                    services.AddSingleton<IWebFrontAuthUnsafeDirectLoginAllowService, BasicDirectLoginAllower>();
                }
            } ) )
            {
                string userName = Guid.NewGuid().ToString();
                int idUser = user.CreateUser( ctx, 1, userName );
                basic.CreateOrUpdateUser( ctx, 1, idUser, "pass" );

                {
                    var payload = new JObject( new JProperty( "userName", userName ), new JProperty( "password", "pass" ) );
                    var param = new JObject( new JProperty( "provider", "Basic" ), new JProperty( "payload", payload ) );
                    HttpResponseMessage authBasic = await server.Client.PostJSON( unsafeDirectLoginUri, param.ToString() );
                    if( allowed )
                    {
                        authBasic.EnsureSuccessStatusCode();
                        var c = RefreshResponse.Parse( server.TypeSystem, authBasic.Content.ReadAsStringAsync().Result );
                        c.Info.Level.Should().Be( AuthLevel.Normal );
                        c.Info.User.UserId.Should().Be( idUser );
                        c.Info.User.Schemes.Select( p => p.Name ).Should().BeEquivalentTo( new[] { "Basic" } );
                        c.Token.Should().NotBeNullOrWhiteSpace();
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
                    HttpResponseMessage authFailed = await server.Client.PostJSON( unsafeDirectLoginUri, param.ToString() );
                    authFailed.StatusCode.Should().Be( HttpStatusCode.Unauthorized );
                    var c = RefreshResponse.Parse( server.TypeSystem, authFailed.Content.ReadAsStringAsync().Result );
                    c.Info.Should().BeNull();
                    c.Token.Should().BeNull();
                }
            }
        }

        [TestCase( "Albert", "pass" )]
        [TestCase( "Paula", "pass" )]
        public async Task basic_authentication_on_user( string userName, string password )
        {
            var user = TestHelper.StObjMap.StObjs.Obtain<UserTable>();
            var basic = TestHelper.StObjMap.StObjs.Obtain<IBasicAuthenticationProvider>();
            using( var ctx = new SqlStandardCallContext() )
            using( var server = new AuthServer() )
            {
                int idUser = await user.CreateUserAsync( ctx, 1, userName );
                if( idUser == -1 ) idUser = await user.FindByNameAsync( ctx, userName );
                await basic.CreateOrUpdatePasswordUserAsync( ctx, 1, idUser, password );

                {
                    var payload = new JObject(
                                        new JProperty( "userName", userName ),
                                        new JProperty( "password", password ) );
                    HttpResponseMessage authBasic = await server.Client.PostJSON( basicLoginUri, payload.ToString() );
                    var c = RefreshResponse.Parse( server.TypeSystem, await authBasic.Content.ReadAsStringAsync() );
                    c.Info.Level.Should().Be( AuthLevel.Normal );
                    c.Info.User.UserId.Should().Be( idUser );
                    c.Info.User.Schemes.Select( p => p.Name ).Should().BeEquivalentTo( new[] { "Basic" } );
                    c.Token.Should().NotBeNullOrWhiteSpace();
                }

                {
                    var payload = new JObject(
                                        new JProperty( "userName", userName ),
                                        new JProperty( "password", "failed" + password ) );
                    HttpResponseMessage authFailed = await server.Client.PostJSON( basicLoginUri, payload.ToString() );
                    var c = RefreshResponse.Parse( server.TypeSystem, await authFailed.Content.ReadAsStringAsync() );
                    c.Info.Should().BeNull();
                    c.Token.Should().BeNull();
                }
            }
        }

        [Test]
        public async Task unsafe_direct_login_returns_BadRequest_and_JSON_ArgumentException_when_payload_is_not_in_the_expected_format()
        {
            using( var server = new AuthServer( options: null, configureServices: services =>
            {
                services.AddSingleton<IWebFrontAuthUnsafeDirectLoginAllowService, BasicDirectLoginAllower>();
            } ) )
            {
                // Missing userName or userId.
                {
                    var param = new JObject( new JProperty( "provider", "Basic" ),
                                             new JProperty( "payload",
                                                    new JObject( new JProperty( "password", "pass" ) ) ) );
                    HttpResponseMessage m = await server.Client.PostJSON( unsafeDirectLoginUri, param.ToString() );
                    m.StatusCode.Should().Be( HttpStatusCode.BadRequest );
                    RefreshResponse r = RefreshResponse.Parse( server.TypeSystem, await m.Content.ReadAsStringAsync() );
                    r.ErrorId.Should().Be( "System.ArgumentException" );
                    r.ErrorText.Should().Contain( "Invalid payload. Missing 'UserId' -> int or 'UserName' -> string" );
                }
                // Missing password.
                {
                    var param = new JObject( new JProperty( "provider", "Basic" ),
                                             new JProperty( "payload",
                                                    new JObject( new JProperty( "userId", "3712" ) ) ) );
                    HttpResponseMessage m = await server.Client.PostJSON( unsafeDirectLoginUri, param.ToString() );
                    m.StatusCode.Should().Be( HttpStatusCode.BadRequest );
                    RefreshResponse r = RefreshResponse.Parse( server.TypeSystem, await m.Content.ReadAsStringAsync() );
                    r.ErrorId.Should().Be( "System.ArgumentException" );
                    r.ErrorText.Should().Contain( "Invalid payload. Missing 'Password' -> string entry." );
                }
                // Totally invalid payload.
                {
                    var param = new JObject( new JProperty( "provider", "Basic" ),
                                             new JProperty( "payload", null ) );
                    HttpResponseMessage m = await server.Client.PostJSON( unsafeDirectLoginUri, param.ToString() );
                    m.StatusCode.Should().Be( HttpStatusCode.BadRequest );
                    RefreshResponse r = RefreshResponse.Parse( server.TypeSystem, await m.Content.ReadAsStringAsync() );
                    r.ErrorId.Should().Be( "System.ArgumentException" );
                    r.ErrorText.Should().Contain( "Invalid payload. It must be either a Tuple<int,string>, a Tuple<string,string> or a IDictionary<string,object> or IEnumerable<KeyValuePair<string,object>> with 'Password' -> string and 'UserId' -> int or 'UserName' -> string entries." );
                }
            }
        }

        /// <summary>
        /// Client calls login with userData that contains a Zone.
        /// </summary>
        class NoEvilZoneForPaula : IWebFrontAuthValidateLoginService
        {
            public Task ValidateLoginAsync( IActivityMonitor monitor, IUserInfo loggedInUser, IWebFrontAuthValidateLoginContext context )
            {
                if( loggedInUser.UserName == "Paula"
                    && context.UserData.Any( kv => kv.Key == "zone" && kv.Value == "<&>vil") )
                {
                    context.SetError( "Validation", "Paula must not go in the <&>vil Zone!" );
                }
                return Task.CompletedTask;
            }
        }

        class BasicDirectLoginAllower : IWebFrontAuthUnsafeDirectLoginAllowService
        {
            public Task<bool> AllowAsync( HttpContext ctx, IActivityMonitor monitor, string scheme, object payload )
            {
                return Task.FromResult( scheme == "Basic" );
            }
        }

        [TestCase( "Albert", "pass", true )]
        [TestCase( "Paula", "pass", false )]
        public async Task IWebFrontAuthValidateLoginService_can_prevent_unsafe_direct_login( string userName, string password, bool okInEvil )
        {
            var user = TestHelper.StObjMap.StObjs.Obtain<UserTable>();
            var basic = TestHelper.StObjMap.StObjs.Obtain<IBasicAuthenticationProvider>();
            using( var ctx = new SqlStandardCallContext() )
            using( var server = new AuthServer( null, services =>
            {
                services.AddSingleton<IWebFrontAuthUnsafeDirectLoginAllowService, BasicDirectLoginAllower>();
                services.AddSingleton<IWebFrontAuthValidateLoginService, NoEvilZoneForPaula>();
            } ) )
            {
                await ctx[user].Connection.EnsureOpenAsync();
                int idUser = await user.CreateUserAsync( ctx, 1, userName );
                if( idUser == -1 ) idUser = await user.FindByNameAsync( ctx, userName );
                await basic.CreateOrUpdatePasswordUserAsync( ctx, 1, idUser, password );

                {
                    var param = new JObject(
                                        new JProperty( "provider", "Basic" ),
                                        new JProperty( "payload", new JObject(
                                            new JProperty( "userName", userName ),
                                            new JProperty( "password", password ) ) ),
                                        new JProperty( "userData", new JObject(
                                                new JProperty( "zone", "good" ) ) ) );
                    HttpResponseMessage authBasic = await server.Client.PostJSON( unsafeDirectLoginUri, param.ToString() );
                    var c = RefreshResponse.Parse( server.TypeSystem, await authBasic.Content.ReadAsStringAsync() );
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
                    HttpResponseMessage auth = await server.Client.PostJSON( unsafeDirectLoginUri, param.ToString() );
                    var c = RefreshResponse.Parse( server.TypeSystem, await auth.Content.ReadAsStringAsync() );
                    if( okInEvil )
                    {
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
                        c.Info.Should().BeNull();
                        c.Token.Should().BeNull();
                        c.ErrorId.Should().Be( "Validation" );
                        c.ErrorText.Should().Be( "Paula must not go in the <&>vil Zone!" );
                        c.UserData.Should().Contain( new[] { new KeyValuePair<string, string>( "zone", "<&>vil" ) } );
                    }
                }
            }
        }

        [TestCase( "Albert", "pass", true )]
        [TestCase( "Paula", "pass", false )]
        public async Task IWebFrontAuthValidateLoginService_can_prevent_basic_login( string userName, string password, bool okInEvil )
        {
            var user = TestHelper.StObjMap.StObjs.Obtain<UserTable>();
            var basic = TestHelper.StObjMap.StObjs.Obtain<IBasicAuthenticationProvider>();
            using( var ctx = new SqlStandardCallContext() )
            using( var server = new AuthServer( null, services =>
            {
                services.AddSingleton<IWebFrontAuthValidateLoginService, NoEvilZoneForPaula>();
            } ) )
            {
                await ctx[user].Connection.EnsureOpenAsync();
                int idUser = await user.CreateUserAsync( ctx, 1, userName );
                if( idUser == -1 ) idUser = await user.FindByNameAsync( ctx, userName );
                await basic.CreateOrUpdatePasswordUserAsync( ctx, 1, idUser, password );

                {
                    // Zone is "good".
                    var payload = new JObject(
                                        new JProperty( "userName", userName ),
                                        new JProperty( "password", password ),
                                        new JProperty( "userData", new JObject(
                                                new JProperty( "zone", "good" ) ) ) );
                    HttpResponseMessage authBasic = await server.Client.PostJSON( basicLoginUri, payload.ToString() );
                    var c = RefreshResponse.Parse( server.TypeSystem, await authBasic.Content.ReadAsStringAsync() );
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
HttpResponseMessage auth = await server.Client.PostJSON( basicLoginUri, payload.ToString() );
var c = RefreshResponse.Parse( server.TypeSystem, await auth.Content.ReadAsStringAsync() );
if( okInEvil ) // When userName is "Albert".
{
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
    c.Info.Should().BeNull();
    c.Token.Should().BeNull();
    c.ErrorId.Should().Be( "Validation" );
    c.ErrorText.Should().Be( "Paula must not go in the <&>vil Zone!" );
    c.UserData.Should().Contain( new[] { new KeyValuePair<string, string>( "zone", "<&>vil" ) } );
}
                }
            }
        }

    }

}
