using CK.AspNet.Auth;
using CK.AspNet.Tester;
using CK.Auth;
using CK.Core;
using CK.DB.Actor;
using CK.DB.Auth;
using CK.DB.User.UserGoogle;
using CK.SqlServer;
using FluentAssertions;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using NUnit.Framework;
using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

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
                return r;
            }
        }

        [Test]
        public async Task unsafe_direct_login_returns_BadRequest_and_JSON_ArgumentException_when_payload_is_not_in_the_expected_format()
        {
            using( var server = new AuthServer( opt => opt.UnsafeDirectLoginAllower = ( httpCtx, scheme ) => scheme == "Basic" ) )
            {
                // Missing userName or userId.
                {
                    var payload = new JObject( new JProperty( "password", "pass" ) );
                    var param = new JObject( new JProperty( "provider", "Basic" ), new JProperty( "payload", payload ) );
                    HttpResponseMessage m = await server.Client.PostJSON( unsafeDirectLoginUri, param.ToString() );
                    m.StatusCode = HttpStatusCode.BadRequest;
                    string content = m.Content.ReadAsStringAsync().Result;
                    JObject r = JObject.Parse( content );
                    ((string)r["errorId"]).Should().Be( "System.ArgumentException" );
                    ((string)r["errorText"]).Should().Contain( "Invalid payload. Missing 'UserId' -> int or 'UserName' -> string" );
                }
                // Missing password.
                {
                    var payload = new JObject( new JProperty( "userId", "3712" ) );
                    var param = new JObject( new JProperty( "provider", "Basic" ), new JProperty( "payload", payload ) );
                    HttpResponseMessage m = await server.Client.PostJSON( unsafeDirectLoginUri, param.ToString() );
                    m.StatusCode = HttpStatusCode.BadRequest;
                    string content = m.Content.ReadAsStringAsync().Result;
                    JObject r = JObject.Parse( content );
                    ((string)r["errorId"]).Should().Be( "System.ArgumentException" );
                    ((string)r["errorText"]).Should().Contain( "Invalid payload. Missing 'Password' -> string entry." );
                }
                // Totally invalid payload.
                {
                    var param = new JObject( new JProperty( "provider", "Basic" ), new JProperty( "payload", null ) );
                    HttpResponseMessage m = await server.Client.PostJSON( unsafeDirectLoginUri, param.ToString() );
                    m.StatusCode = HttpStatusCode.BadRequest;
                    string content = m.Content.ReadAsStringAsync().Result;
                    JObject r = JObject.Parse( content );
                    ((string)r["errorId"]).Should().Be( "System.ArgumentException" );
                    ((string)r["errorText"]).Should().Contain( "Invalid payload. It must be either a Tuple<int,string>, a Tuple<string,string> or a IDictionary<string,object> or IEnumerable<KeyValuePair<string,object>> with 'Password' -> string and 'UserId' -> int or 'UserName' -> string entries." );
                }

            }
        }

        [TestCase( true )]
        [TestCase( false )]
        public async Task basic_authentication_via_generic_wrapper_on_a_created_user( bool allowed )
        {
            var user = TestHelper.StObjMap.Default.Obtain<UserTable>();
            var auth = TestHelper.StObjMap.Default.Obtain<IAuthenticationDatabaseService>();
            var basic = auth.FindProvider( "Basic" );
   
            using( var ctx = new SqlStandardCallContext() )
            using( var server = new AuthServer( opt =>
            {
                if( allowed )
                {
                    opt.UnsafeDirectLoginAllower = ( httpCtx, scheme ) => scheme == "Basic";
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
            var user = TestHelper.StObjMap.Default.Obtain<UserTable>();
            var basic = TestHelper.StObjMap.Default.Obtain<IBasicAuthenticationProvider>();
            using( var ctx = new SqlStandardCallContext() )
            using( var server = new AuthServer() )
            {
                user.FindByName( ctx, "MKLJHZDJKH" );
                int idUser = user.CreateUser( ctx, 1, userName );
                if( idUser == -1 ) idUser = user.FindByName( ctx, userName );
                basic.CreateOrUpdatePasswordUser( ctx, 1, idUser, password );

                {
                    HttpResponseMessage authBasic = await server.Client.PostJSON( basicLoginUri, new JObject( new JProperty( "userName", userName ), new JProperty( "password", password ) ).ToString() );
                    var c = RefreshResponse.Parse( server.TypeSystem, authBasic.Content.ReadAsStringAsync().Result );
                    c.Info.Level.Should().Be( AuthLevel.Normal );
                    c.Info.User.UserId.Should().Be( idUser );
                    c.Info.User.Schemes.Select( p => p.Name ).Should().BeEquivalentTo( new[] { "Basic" } );
                    c.Token.Should().NotBeNullOrWhiteSpace();
                }

                {
                    HttpResponseMessage authFailed = await server.Client.PostJSON( basicLoginUri, new JObject( new JProperty( "userName", userName ), new JProperty( "password", "failed" + password ) ).ToString() );
                    var c = RefreshResponse.Parse( server.TypeSystem, authFailed.Content.ReadAsStringAsync().Result );
                    c.Info.Should().BeNull();
                    c.Token.Should().BeNull();
                }
            }
        }
    }

}
