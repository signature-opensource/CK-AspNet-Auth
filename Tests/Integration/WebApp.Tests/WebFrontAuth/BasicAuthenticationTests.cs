using CK.AspNet.Auth;
using CK.AspNet.Tester;
using CK.Auth;
using FluentAssertions;
using Newtonsoft.Json.Linq;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace WebApp.Tests
{
    [TestFixture]
    public class BasicAuthenticationTests
    {
        readonly Dictionary<string, string> _userToken = new Dictionary<string, string>();
        TestClient _client;

        [SetUp]
        public void Initialize() => _client = WebAppHelper.GetRunningTestClient().GetAwaiter().GetResult();

        [TestCase( "Albert", "pass" )]
        public async Task login_basic_for_known_user_with_invalid_password( string userName, string password )
        {
            await EnsureTokenFor( userName, password );
            HttpResponseMessage authFailed = await _client.PostJSON( WebAppUrl.BasicLoginUri, new JObject( new JProperty( "userName", userName ), new JProperty( "password", "failed" + password ) ).ToString() );
            var c = RefreshResponse.Parse( WebAppHelper.AuthTypeSystem, await authFailed.Content.ReadAsStringAsync() );
            c.Info.Should().BeNull();
            c.Token.Should().BeNull();
        }

        [TestCase( "Albert", "pass" )]
        public async Task calling_token_endpoint( string userName, string password )
        {
            {
                // With token: it always works.
                _client.Token = await EnsureTokenFor( userName, password );
                HttpResponseMessage req = await _client.Get( WebAppUrl.TokenExplainUri );
                var tokenClear = await req.Content.ReadAsStringAsync();
                tokenClear.Should().Contain( "Albert" );
            }
            {
                // Without token: it works only when CookieMode is AuthenticationCookieMode.RootPath.
                _client.Token = null;
                HttpResponseMessage req = await _client.Get( WebAppUrl.TokenExplainUri );
                var tokenClear = await req.Content.ReadAsStringAsync();
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


        async Task<string> EnsureTokenFor( string userName, string password )
        {
            string token;
            if( _userToken.TryGetValue( userName, out token ) ) return token;

            HttpResponseMessage ensure = await _client.PostJSON( WebAppUrl.EnsureBasicUser, new JObject( new JProperty( "userName", userName ), new JProperty( "password", password ) ).ToString() );
            ensure.EnsureSuccessStatusCode();

            RefreshResponse c = await BasicLogin( _client, userName, password );
            _userToken.Add( userName, c.Token );
            return c.Token;
        }

        static public async Task<RefreshResponse> BasicLogin( TestClient client, string userName, string password )
        {
            HttpResponseMessage authBasic = await client.PostJSON( WebAppUrl.BasicLoginUri, new JObject( new JProperty( "userName", userName ), new JProperty( "password", password ) ).ToString() );
            var c = RefreshResponse.Parse( WebAppHelper.AuthTypeSystem, authBasic.Content.ReadAsStringAsync().Result );
            c.Info.Level.Should().Be( AuthLevel.Normal );
            c.Info.User.UserId.Should().BeGreaterThan( 1 );
            c.Info.User.Schemes.Select( p => p.Name ).Should().BeEquivalentTo( new[] { "Basic" } );
            c.Token.Should().NotBeNullOrWhiteSpace();
            return c;
        }
    }
}
