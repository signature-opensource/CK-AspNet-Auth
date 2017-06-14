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
        const string basicLoginUri = "/.webfront/c/basicLogin";
        const string loginUri = "/.webfront/c/login";
        const string refreshUri = "/.webfront/c/refresh";
        const string logoutUri = "/.webfront/c/logout";
        const string tokenExplainUri = "/.webfront/token";

        readonly IAuthenticationTypeSystem _typeSytem = new StdAuthenticationTypeSystem();
        readonly Dictionary<string,string> _userToken = new Dictionary<string, string>();
        TestClient _client;

        [SetUp]
        public void Initialize() => _client = new TestClient("http://localhost:4324/");

        [TearDown]
        public void Uninitialize() => _client.Dispose();

        [TestCase("Albert","pass")]
        public void login_basic_for_known_user( string userName, string password )
        {
            EnsureTokenFor(userName, password);
            HttpResponseMessage authFailed = _client.Post(basicLoginUri, new JObject(new JProperty("userName", userName), new JProperty("password", "failed" + password)).ToString());
            var c = RefreshResponse.Parse(_typeSytem, authFailed.Content.ReadAsStringAsync().Result);
            c.Info.Should().BeNull();
            c.Token.Should().BeNull();
        }

        [TestCase("Albert", "pass")]
        public void calling_token_endpoint(string userName, string password)
        {
            {
                // With token: it always works.
                _client.Token = EnsureTokenFor(userName,password);
                HttpResponseMessage req = _client.Get(tokenExplainUri);
                var tokenClear = req.Content.ReadAsStringAsync().Result;
                tokenClear.Should().Contain("Albert");
            }
            {
                // Without token: it works only when CookieMode is AuthenticationCookieMode.RootPath.
                _client.Token = null;
                HttpResponseMessage req = _client.Get(tokenExplainUri);
                var tokenClear = req.Content.ReadAsStringAsync().Result;
                if (_client.Cookies.GetCookies(_client.BaseAddress).Count > 0 )
                {
                    // Authentication Cookie has been used.
                    tokenClear.Should().Contain("Albert");
                }
                else
                {
                    tokenClear.Should().NotContain("Albert");
                }
            }
        }


            string EnsureTokenFor(string userName, string password)
        {
            string token;
            if (_userToken.TryGetValue(userName, out token)) return token;
            HttpResponseMessage authBasic = _client.Post(basicLoginUri, new JObject(new JProperty("userName", userName), new JProperty("password", password)).ToString());
            var c = RefreshResponse.Parse(_typeSytem, authBasic.Content.ReadAsStringAsync().Result);
            c.Info.Level.Should().Be(AuthLevel.Normal);
            c.Info.User.UserId.Should().BeGreaterThan(1);
            c.Info.User.Schemes.Select(p => p.Name).ShouldBeEquivalentTo(new[] { "Basic" });
            c.Token.Should().NotBeNullOrWhiteSpace();
            _userToken.Add(userName,c.Token);
            return c.Token;
        }
    }
}
