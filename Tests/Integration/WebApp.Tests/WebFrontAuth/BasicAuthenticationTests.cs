using CK.AspNet.Auth;
using CK.Auth;
using FluentAssertions;
using Newtonsoft.Json.Linq;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;

namespace WebApp.Tests
{
    [TestFixture]
    public class BasicAuthenticationTests
    {
        readonly Dictionary<string, string> _userToken = new Dictionary<string, string>();
        TestClient _client;

        [SetUp]
        public void Initialize() => _client = WebAppHelper.GetRunningTestClient();

        [TestCase( "Albert", "pass" )]
        public void login_basic_for_known_user_with_invalid_password( string userName, string password )
        {
            EnsureTokenFor( userName, password );
            HttpResponseMessage authFailed = _client.Post( WebAppUrl.BasicLoginUri, new JObject( new JProperty( "userName", userName ), new JProperty( "password", "failed" + password ) ).ToString() );
            var c = RefreshResponse.Parse( WebAppHelper.AuthTypeSystem, authFailed.Content.ReadAsStringAsync().Result );
            c.Info.Should().BeNull();
            c.Token.Should().BeNull();
        }

        [TestCase( "Albert", "pass" )]
        public void calling_token_endpoint( string userName, string password )
        {
            {
                // With token: it always works.
                _client.Token = EnsureTokenFor( userName, password );
                HttpResponseMessage req = _client.Get( WebAppUrl.TokenExplainUri );
                var tokenClear = req.Content.ReadAsStringAsync().Result;
                tokenClear.Should().Contain( "Albert" );
            }
            {
                // Without token: it works only when CookieMode is AuthenticationCookieMode.RootPath.
                _client.Token = null;
                HttpResponseMessage req = _client.Get( WebAppUrl.TokenExplainUri );
                var tokenClear = req.Content.ReadAsStringAsync().Result;
                if( _client.Cookies.GetCookies( _client.BaseAddress )[WebFrontAuthService.AuthCookieName] != null )
                {
                    // Authentication Cookie has been used.
                    tokenClear.Should().Contain( "Albert" );
                }
                else
                {
                    tokenClear.Should().NotContain( "Albert" );
                }
            }
        }


        string EnsureTokenFor( string userName, string password )
        {
            string token;
            if( _userToken.TryGetValue( userName, out token ) ) return token;

            HttpResponseMessage ensure = _client.Post( WebAppUrl.EnsureBasicUser, new JObject( new JProperty( "userName", userName ), new JProperty( "password", password ) ).ToString() );
            ensure.EnsureSuccessStatusCode();

            RefreshResponse c = BasicLogin( _client, userName, password );
            _userToken.Add( userName, c.Token );
            return c.Token;
        }

        static public RefreshResponse BasicLogin( TestClient client, string userName, string password )
        {
            HttpResponseMessage authBasic = client.Post( WebAppUrl.BasicLoginUri, new JObject( new JProperty( "userName", userName ), new JProperty( "password", password ) ).ToString() );
            var c = RefreshResponse.Parse( WebAppHelper.AuthTypeSystem, authBasic.Content.ReadAsStringAsync().Result );
            c.Info.Level.Should().Be( AuthLevel.Normal );
            c.Info.User.UserId.Should().BeGreaterThan( 1 );
            c.Info.User.Schemes.Select( p => p.Name ).ShouldBeEquivalentTo( new[] { "Basic" } );
            c.Token.Should().NotBeNullOrWhiteSpace();
            return c;
        }
    }
}
