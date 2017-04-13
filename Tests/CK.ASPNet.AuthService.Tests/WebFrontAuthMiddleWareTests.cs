using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.Hosting;
using CK.Core;
using System;
using FluentAssertions;
using System.Linq;
using CK.DB.Auth;
using Newtonsoft.Json.Linq;
using CK.Auth;
using Microsoft.AspNetCore.Http;
using System.Net;
using System.Security.Claims;

namespace CK.AspNet.AuthService.Tests
{
    [TestFixture]
    public class WithMockServiceTests
    {
        const string basicLoginUri = "/.webFront/c/basicLogin";
        const string refreshUri = "/.webFront/c/refresh";
        const string tokenExplainUri = "/.webFront/token";

        class RefreshResponse
        {
            public IAuthenticationInfo Info { get; set; }

            public string Token { get; set; }

            public static RefreshResponse Parse( IAuthenticationTypeSystem t, string json )
            {
                JObject o = JObject.Parse(json);
                var r = new RefreshResponse();
                if (o["info"].Type == JTokenType.Object)
                {
                    r.Info = t.AuthenticationInfo.FromJObject((JObject)o["info"]);
                }
                r.Token = (string)o["token"];
                return r;
            }
        }

        [Test]
        public void calling_cred_refresh_from_scrath_returns_null_info_and_token()
        {
            using (var s = new AuthServer(new WebFrontAuthMiddlewareOptions(), new MockAuthDatabaseService()))
            {
                HttpResponseMessage response = s.Client.Get(refreshUri);
                response.EnsureSuccessStatusCode();
                var c = RefreshResponse.Parse(s.TypeSystem, response.Content.ReadAsStringAsync().Result);
                c.ShouldBeEquivalentTo(new RefreshResponse());
            }
        }

        [Test]
        public void a_successful_basic_login_returns_valid_info_and_token()
        {
            using (var s = new AuthServer(new WebFrontAuthMiddlewareOptions(), new MockAuthDatabaseService()))
            {
                HttpResponseMessage response = s.Client.Post(basicLoginUri, "{\"userName\":\"Albert\",\"password\":\"success\"}");
                response.EnsureSuccessStatusCode();
                var c = RefreshResponse.Parse(s.TypeSystem, response.Content.ReadAsStringAsync().Result);
                c.Info.User.ActorId.Should().Be(2);
                c.Info.User.DisplayName.Should().Be("Albert");
                c.Info.User.Providers.Should().HaveCount(1);
                c.Info.User.Providers[0].Name.Should().Be("Basic");
                c.Info.User.Providers[0].LastUsed.Should().BeCloseTo( DateTime.UtcNow, 1500 );
                c.Info.ActualUser.Should().BeSameAs(c.Info.User);
                c.Info.Level.Should().Be(AuthLevel.Normal);
                c.Info.IsImpersonated.Should().BeFalse();
                c.Token.Should().NotBeNullOrWhiteSpace();
            }
        }

        [Test]
        public void basic_login_is_404NotFound_when_no_BasicAutheticationProvider_exists()
        {
            using (var s = new AuthServer(new WebFrontAuthMiddlewareOptions(), new MockAuthDatabaseService(false, false)))
            {
                HttpResponseMessage response = s.Client.Post(basicLoginUri, "{\"userName\":\"Albert\",\"password\":\"success\"}");
                response.StatusCode.Should().Be(HttpStatusCode.NotFound);
            }
        }

        [Test]
        public void successful_login_set_the_cookies_on_the_webfront_c_path()
        {
            using (var s = new AuthServer(new WebFrontAuthMiddlewareOptions(), new MockAuthDatabaseService()))
            {
                HttpResponseMessage response = s.Client.Post(basicLoginUri, "{\"userName\":\"Albert\",\"password\":\"success\"}");
                response.EnsureSuccessStatusCode();
                s.Client.Cookies.GetCookies(s.Server.BaseAddress).Should().BeEmpty();
                s.Client.Cookies.GetCookies(new Uri(s.Server.BaseAddress, "/.webFront/c/")).Should().HaveCount(2);
            }
        }

        [Test]
        public void invalid_payload_to_basic_login_returns_a_400_bad_request()
        {
            using (var s = new AuthServer(new WebFrontAuthMiddlewareOptions(), new MockAuthDatabaseService()))
            {
                HttpResponseMessage response = s.Client.Post(basicLoginUri, "{\"userName\":\"\",\"password\":\"success\"}");
                response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
                s.Client.Cookies.GetCookies(new Uri(s.Server.BaseAddress, "/.webFront/c/")).Should().HaveCount(0);
                response = s.Client.Post(basicLoginUri, "{\"userName\":\"toto\",\"password\":\"\"}");
                response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
                response = s.Client.Post(basicLoginUri, "not a json");
                response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
            }
        }

        [Test]
        public void simple_token_challenge()
        {
            using (var s = new AuthServer(new WebFrontAuthMiddlewareOptions(), new MockAuthDatabaseService()))
            {
                HttpResponseMessage auth = s.Client.Post(basicLoginUri, "{\"userName\":\"Albert\",\"password\":\"success\"}");
                var c = RefreshResponse.Parse(s.TypeSystem, auth.Content.ReadAsStringAsync().Result);
                s.Client.SetToken(c.Token);
                HttpResponseMessage req = s.Client.Get(tokenExplainUri);
                var tokenClear = auth.Content.ReadAsStringAsync().Result;
            }
        }


    }
}
