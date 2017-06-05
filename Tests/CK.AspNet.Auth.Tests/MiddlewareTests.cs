using CK.AspNet.Tester;
using CK.Auth;
using FluentAssertions;
using Newtonsoft.Json.Linq;
using NUnit.Framework;
using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;

namespace CK.AspNet.Auth.Tests
{
    [TestFixture]
    public class MiddlewareTests
    {
        const string basicLoginUri = "/.webfront/c/basicLogin";
        const string loginProviderUri = "/.webfront/c/login";
        const string refreshUri = "/.webfront/c/refresh";
        const string logoutUri = "/.webfront/c/logout";
        const string tokenExplainUri = "/.webfront/token";

        class RefreshResponse
        {
            public IAuthenticationInfo Info { get; set; }

            public string Token { get; set; }

            public bool Refreshable { get; set; }

            public string[] Providers { get; set; }

            public static RefreshResponse Parse( IAuthenticationTypeSystem t, string json )
            {
                JObject o = JObject.Parse(json);
                var r = new RefreshResponse();
                if (o["info"].Type == JTokenType.Object)
                {
                    r.Info = t.AuthenticationInfo.FromJObject((JObject)o["info"]);
                }
                r.Token = (string)o["token"];
                r.Refreshable = (bool)o["refreshable"];
                r.Providers = o["providers"]?.Values<string>().ToArray();
                return r;
            }
        }

        [Test]
        public void calling_c_refresh_from_scrath_returns_null_info_and_token()
        {
            using (var s = new AuthServer(new WebFrontAuthMiddlewareOptions()))
            {
                HttpResponseMessage response = s.Client.Get(refreshUri);
                response.EnsureSuccessStatusCode();
                var c = RefreshResponse.Parse(s.TypeSystem, response.Content.ReadAsStringAsync().Result);
                c.ShouldBeEquivalentTo(new RefreshResponse());
            }
        }

        [Test]
        public void calling_c_refresh_from_scrath_with_providers_query_parameter_returns_null_info_and_null_token_but_the_array_of_providers_name()
        {
            using (var s = new AuthServer(new WebFrontAuthMiddlewareOptions()))
            {
                HttpResponseMessage response = s.Client.Get(refreshUri+"?providers");
                response.EnsureSuccessStatusCode();
                var c = RefreshResponse.Parse(s.TypeSystem, response.Content.ReadAsStringAsync().Result);
                c.ShouldBeEquivalentTo(new RefreshResponse() { Providers = new[] { "Basic" } });
            }
        }

        [Test]
        public void a_successful_basic_login_returns_valid_info_and_token()
        {
            using (var s = new AuthServer(new WebFrontAuthMiddlewareOptions()))
            {
                HttpResponseMessage response = s.Client.Post(basicLoginUri, "{\"userName\":\"Albert\",\"password\":\"success\"}");
                response.EnsureSuccessStatusCode();
                var c = RefreshResponse.Parse(s.TypeSystem, response.Content.ReadAsStringAsync().Result);
                c.Info.User.UserId.Should().Be(2);
                c.Info.User.UserName.Should().Be("Albert");
                c.Info.User.Providers.Should().HaveCount(1);
                c.Info.User.Providers[0].Name.Should().Be("Basic");
                c.Info.User.Providers[0].LastUsed.Should().BeCloseTo( DateTime.UtcNow, 1500 );
                c.Info.ActualUser.Should().BeSameAs(c.Info.User);
                c.Info.Level.Should().Be(AuthLevel.Normal);
                c.Info.IsImpersonated.Should().BeFalse();
                c.Token.Should().NotBeNullOrWhiteSpace();
                c.Refreshable.Should().BeFalse("Since by default Options.SlidingExpirationTime is 0.");
            }
        }

        [Test]
        public void basic_login_is_404NotFound_when_no_BasicAuthenticationProvider_exists()
        {
            using (var s = new AuthServer(new WebFrontAuthMiddlewareOptions(), services => services.Replace<WebFrontAuthService, NoAuthWebFrontService>()))
            {
                HttpResponseMessage response = s.Client.Post(basicLoginUri, "{\"userName\":\"Albert\",\"password\":\"success\"}");
                response.StatusCode.Should().Be(HttpStatusCode.NotFound);
            }
        }

        [TestCase(AuthenticationCookieMode.WebFrontPath, false)]
        [TestCase(AuthenticationCookieMode.RootPath, false)]
        [TestCase(AuthenticationCookieMode.WebFrontPath, true)]
        [TestCase(AuthenticationCookieMode.RootPath, true)]
        public void successful_login_set_the_cookies_on_the_webfront_c_path_and_these_cookies_can_be_used_to_restore_the_authentication(AuthenticationCookieMode mode, bool useGenericWrapper)
        {
            using (var s = new AuthServer(new WebFrontAuthMiddlewareOptions() { CookieMode = mode }))
            {
                // Login: the 2 cookies are set on .webFront/c/ path.
                var login = LoginAlbertViaBasicProvider(s, useGenericWrapper);
                DateTime basicLoginTime = login.Info.User.Providers.Single(p => p.Name == "Basic").LastUsed;
                string originalToken = login.Token;
                // Request with token: the authentication is based on the token.
                {
                    s.Client.Token = originalToken;
                    HttpResponseMessage tokenRefresh = s.Client.Get(refreshUri);
                    tokenRefresh.EnsureSuccessStatusCode();
                    var c = RefreshResponse.Parse(s.TypeSystem, tokenRefresh.Content.ReadAsStringAsync().Result);
                    c.Info.Level.Should().Be(AuthLevel.Normal);
                    c.Info.User.UserName.Should().Be("Albert");
                    c.Info.User.Providers.Single(p => p.Name == "Basic").LastUsed.Should().Be(basicLoginTime);
                }
                // Token less request: the authentication is restored from the cookie.
                {
                    s.Client.Token = null;
                    HttpResponseMessage tokenLessRefresh = s.Client.Get(refreshUri);
                    tokenLessRefresh.EnsureSuccessStatusCode();
                    var c = RefreshResponse.Parse(s.TypeSystem, tokenLessRefresh.Content.ReadAsStringAsync().Result);
                    c.Info.Level.Should().Be(AuthLevel.Normal);
                    c.Info.User.UserName.Should().Be("Albert");
                    c.Info.User.Providers.Single(p => p.Name == "Basic").LastUsed.Should().Be(basicLoginTime);
                }
                // Request with token and ?providers query parametrers: we receive the providers.
                {
                    s.Client.Token = originalToken;
                    HttpResponseMessage tokenRefresh = s.Client.Get(refreshUri+"?providers");
                    tokenRefresh.EnsureSuccessStatusCode();
                    var c = RefreshResponse.Parse(s.TypeSystem, tokenRefresh.Content.ReadAsStringAsync().Result);
                    c.Info.Level.Should().Be(AuthLevel.Normal);
                    c.Info.User.UserName.Should().Be("Albert");
                    c.Info.User.Providers.Single(p => p.Name == "Basic").LastUsed.Should().Be(basicLoginTime);
                    c.Providers.Should().ContainSingle( "Basic" );
                }
            }
        }

        [TestCase(AuthenticationCookieMode.WebFrontPath)]
        [TestCase(AuthenticationCookieMode.RootPath)]
        public void bad_tokens_are_ignored(AuthenticationCookieMode mode)
        {
            using (var s = new AuthServer(new WebFrontAuthMiddlewareOptions() { CookieMode = mode }))
            {
                var firstLogin = LoginAlbertViaBasicProvider(s);
                string badToken = firstLogin.Token + 'B';
                s.Client.Token = badToken;
                RefreshResponse c = CallRefreshEndPoint(s);
                c.Info.Should().BeNull();
                HttpResponseMessage tokenRead = s.Client.Get(tokenExplainUri);
                tokenRead.Content.ReadAsStringAsync().Result.Should().Be("{}");
            }
        }

        [TestCase(AuthenticationCookieMode.WebFrontPath, true)]
        [TestCase(AuthenticationCookieMode.RootPath, true)]
        [TestCase(AuthenticationCookieMode.WebFrontPath, false)]
        [TestCase(AuthenticationCookieMode.RootPath, false)]
        public void logout_without_full_query_parameter_removes_the_authentication_cookie_but_keeps_the_unsafe_one(AuthenticationCookieMode mode, bool logoutWithToken)
        {
            using (var s = new AuthServer(new WebFrontAuthMiddlewareOptions() { CookieMode = mode } ))
            {
                // Login: the 2 cookies are set.
                var firstLogin = LoginAlbertViaBasicProvider(s);
                DateTime basicLoginTime = firstLogin.Info.User.Providers.Single(p => p.Name == "Basic").LastUsed;
                string originalToken = firstLogin.Token;
                // Logout 
                if (logoutWithToken) s.Client.Token = originalToken;
                HttpResponseMessage logout = s.Client.Get(logoutUri);
                logout.EnsureSuccessStatusCode();
                // Refresh: we have the Unsafe Albert.
                s.Client.Token = null;
                RefreshResponse c = CallRefreshEndPoint(s);
                c.Info.Level.Should().Be(AuthLevel.Unsafe);
                c.Info.User.UserName.Should().Be("");
                c.Info.UnsafeUser.UserName.Should().Be("Albert");
                c.Info.UnsafeUser.Providers.Single(p => p.Name == "Basic").LastUsed.Should().Be(basicLoginTime);
            }
        }

        [TestCase(AuthenticationCookieMode.WebFrontPath, true)]
        [TestCase(AuthenticationCookieMode.RootPath, true)]
        [TestCase(AuthenticationCookieMode.WebFrontPath, false)]
        [TestCase(AuthenticationCookieMode.RootPath, false)]
        public void logout_with_full_query_parameter_removes_both_cookies(AuthenticationCookieMode mode, bool logoutWithToken)
        {
            using (var s = new AuthServer(new WebFrontAuthMiddlewareOptions() { CookieMode = mode }))
            {
                // Login: the 2 cookies are set.
                var firstLogin = LoginAlbertViaBasicProvider(s);
                DateTime basicLoginTime = firstLogin.Info.User.Providers.Single(p => p.Name == "Basic").LastUsed;
                string originalToken = firstLogin.Token;
                // Logout 
                if (logoutWithToken) s.Client.Token = originalToken;
                HttpResponseMessage logout = s.Client.Get(logoutUri+"?full");
                logout.EnsureSuccessStatusCode();
                // Refresh: no authentication.
                s.Client.Token = null;
                HttpResponseMessage tokenRefresh = s.Client.Get(refreshUri);
                tokenRefresh.EnsureSuccessStatusCode();
                var c = RefreshResponse.Parse(s.TypeSystem, tokenRefresh.Content.ReadAsStringAsync().Result);
                c.Info.Should().BeNull();
                c.Token.Should().BeNull();
            }
        }

        [Test]
        public void invalid_payload_to_basic_login_returns_a_400_bad_request()
        {
            using (var s = new AuthServer(new WebFrontAuthMiddlewareOptions()))
            {
                HttpResponseMessage response = s.Client.Post(basicLoginUri, "{\"userName\":\"\",\"password\":\"success\"}");
                response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
                s.Client.Cookies.GetCookies(new Uri(s.Server.BaseAddress, "/.webfront/c/")).Should().HaveCount(0);
                response = s.Client.Post(basicLoginUri, "{\"userName\":\"toto\",\"password\":\"\"}");
                response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
                response = s.Client.Post(basicLoginUri, "not a json");
                response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
            }
        }

        [TestCase(false, Description = "With cookies on the .webfront path.")]
        [TestCase(true, Description = "With cookies on the root path.")]
        public void webfront_token_endpoint_returns_the_current_authentication_indented_JSON_and_enables_to_test_actual_authentication( bool rootCookiePath )
        {
            using (var s = new AuthServer(new WebFrontAuthMiddlewareOptions()
            {
                CookieMode = rootCookiePath ? AuthenticationCookieMode.RootPath : AuthenticationCookieMode.WebFrontPath
            }))
            {
                HttpResponseMessage auth = s.Client.Post(basicLoginUri, "{\"userName\":\"Albert\",\"password\":\"success\"}");
                var c = RefreshResponse.Parse(s.TypeSystem, auth.Content.ReadAsStringAsync().Result);
                {
                    // With token: it always works.
                    s.Client.Token = c.Token;
                    HttpResponseMessage req = s.Client.Get(tokenExplainUri);
                    var tokenClear = req.Content.ReadAsStringAsync().Result;
                    tokenClear.Should().Contain("Albert");
                }
                {
                    // Without token: it works only when CookieMode is AuthenticationCookieMode.RootPath.
                    s.Client.Token = null;
                    HttpResponseMessage req = s.Client.Get(tokenExplainUri);
                    var tokenClear = req.Content.ReadAsStringAsync().Result;
                    if(rootCookiePath)
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
        }


        [Test]
        public void SlidingExpiration_works_as_expected_in_bearer_only_mode_by_calling_refresh_endpoint()
        {
            using (var s = new AuthServer(new WebFrontAuthMiddlewareOptions()
            {
                ExpireTimeSpan = TimeSpan.FromSeconds(2.0),
                SlidingExpirationTime = TimeSpan.FromSeconds(10)
            }))
            {
                // This test is far from perfect but does the job without clock injection.
                RefreshResponse auth = LoginAlbertViaBasicProvider(s);
                DateTime next = auth.Info.Expires.Value - TimeSpan.FromSeconds(1.7);
                while (next > DateTime.UtcNow) ;
                RefreshResponse refresh = CallRefreshEndPoint(s);
                refresh.Info.Expires.Value.Should().BeAfter(auth.Info.Expires.Value, "Refresh increased the expiration time.");
            }
        }

        [Test]
        public void SlidingExpiration_works_as_expected_in_rooted_Cookie_mode_where_any_request_can_do_the_job()
        {
            using (var s = new AuthServer(new WebFrontAuthMiddlewareOptions()
            {
                CookieMode = AuthenticationCookieMode.RootPath,
                ExpireTimeSpan = TimeSpan.FromSeconds(2.0),
                SlidingExpirationTime = TimeSpan.FromSeconds(10)
            }))
            {
                // This test is far from perfect but does the job without clock injection.
                RefreshResponse auth = LoginAlbertViaBasicProvider(s);
                DateTime expCookie1 = s.Client.Cookies.GetCookies(s.Server.BaseAddress)[".webFront"].Expires.ToUniversalTime();
                expCookie1.Should().BeCloseTo(auth.Info.Expires.Value, precision: 1000);
                DateTime next = auth.Info.Expires.Value - TimeSpan.FromSeconds(1.7);
                while (next > DateTime.UtcNow) ;

                // Calling token endpoint (like any other endpoint that sollicitates authentication) is enough.
                HttpResponseMessage req = s.Client.Get(tokenExplainUri);
                IAuthenticationInfo refresh = s.TypeSystem.AuthenticationInfo.FromJObject(JObject.Parse(req.Content.ReadAsStringAsync().Result));
                refresh.Expires.Value.Should().BeAfter(auth.Info.Expires.Value, "Token life time has been increased.");

                DateTime expCookie2 = s.Client.Cookies.GetCookies(s.Server.BaseAddress)[".webFront"].Expires.ToUniversalTime();
                expCookie2.Should().BeCloseTo(refresh.Expires.Value, precision: 1000);
            }
        }

        static RefreshResponse LoginAlbertViaBasicProvider(AuthServer s, bool useGenericWrapper = false)
        {
            HttpResponseMessage response = useGenericWrapper
                                            ? s.Client.Post(loginProviderUri, "{ \"Provider\":\"Basic\", \"Payload\": {\"userName\":\"Albert\",\"password\":\"success\"} }")
                                            : s.Client.Post(basicLoginUri, "{\"userName\":\"Albert\",\"password\":\"success\"}");
            response.EnsureSuccessStatusCode();
            switch(s.Options.CookieMode)
            {
                case AuthenticationCookieMode.WebFrontPath:
                    {
                        s.Client.Cookies.GetCookies(s.Server.BaseAddress).Should().BeEmpty();
                        s.Client.Cookies.GetCookies(new Uri(s.Server.BaseAddress, "/.webfront/c/")).Should().HaveCount(2);
                        break;
                    }
                case AuthenticationCookieMode.RootPath:
                    {
                        s.Client.Cookies.GetCookies(s.Server.BaseAddress).Should().HaveCount(2);
                        break;
                    }
                case AuthenticationCookieMode.None:
                    {
                        s.Client.Cookies.GetCookies(s.Server.BaseAddress).Should().BeEmpty();
                        s.Client.Cookies.GetCookies(new Uri(s.Server.BaseAddress, "/.webfront/c/")).Should().BeEmpty();
                        break;
                    }
            }
            var c = RefreshResponse.Parse(s.TypeSystem, response.Content.ReadAsStringAsync().Result);
            c.Info.Level.Should().Be(AuthLevel.Normal);
            c.Info.User.UserName.Should().Be("Albert");
            return c;
        }
        private static RefreshResponse CallRefreshEndPoint(AuthServer s)
        {
            HttpResponseMessage tokenRefresh = s.Client.Get(refreshUri);
            tokenRefresh.EnsureSuccessStatusCode();
            return RefreshResponse.Parse(s.TypeSystem, tokenRefresh.Content.ReadAsStringAsync().Result);
        }

    }
}
