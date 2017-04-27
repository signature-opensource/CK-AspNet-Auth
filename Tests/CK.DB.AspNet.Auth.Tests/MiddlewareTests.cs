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

namespace CK.DB.AspNet.Auth.Tests
{
    [TestFixture]
    public class MiddlewareTests
    {
        const string basicLoginUri = "/.webFront/c/basicLogin";
        const string loginUri = "/.webFront/c/login";
        const string refreshUri = "/.webFront/c/refresh";
        const string logoutUri = "/.webFront/c/logout";
        const string tokenExplainUri = "/.webFront/token";

        class RefreshResponse
        {
            public IAuthenticationInfo Info { get; set; }

            public string Token { get; set; }

            public bool Refreshable { get; set; }

            public static RefreshResponse Parse(IAuthenticationTypeSystem t, string json)
            {
                JObject o = JObject.Parse(json);
                var r = new RefreshResponse();
                if (o["info"].Type == JTokenType.Object)
                {
                    r.Info = t.AuthenticationInfo.FromJObject((JObject)o["info"]);
                }
                r.Token = (string)o["token"];
                r.Refreshable = (bool)o["refreshable"];
                return r;
            }
        }

        [Test]
        public void basic_authentication_via_generic_wrapper_on_a_created_user()
        {
            var user = TestHelper.StObjMap.Default.Obtain<UserTable>();
            var auth = TestHelper.StObjMap.Default.Obtain<IAuthenticationDatabaseService>();
            var basic = auth.FindProvider("Basic");
            using (var ctx = new SqlStandardCallContext())
            using (var server = new AuthServer(new WebFrontAuthMiddlewareOptions()))
            {
                string userName = Guid.NewGuid().ToString();
                int idUser = user.CreateUser(ctx, 1, userName);
                basic.CreateOrUpdateUser(ctx, 1, idUser, "pass");

                {
                    var payload = new JObject(new JProperty("userName", userName), new JProperty("password", "pass"));
                    var param = new JObject(new JProperty("provider", "Basic"), new JProperty("payload", payload));
                    HttpResponseMessage authBasic = server.Client.Post(loginUri, param.ToString());
                    var c = RefreshResponse.Parse(server.TypeSystem, authBasic.Content.ReadAsStringAsync().Result);
                    c.Info.Level.Should().Be(AuthLevel.Normal);
                    c.Info.User.UserId.Should().Be(idUser);
                    c.Info.User.Providers.Select(p => p.Name).ShouldBeEquivalentTo(new[] { "Basic" });
                    c.Token.Should().NotBeNullOrWhiteSpace();
                }

                {
                    var payload = new JObject(new JProperty("userName", userName), new JProperty("password", "failed"));
                    var param = new JObject(new JProperty("provider", "Basic"), new JProperty("payload", payload));
                    HttpResponseMessage authFailed = server.Client.Post(loginUri, param.ToString());
                    var c = RefreshResponse.Parse(server.TypeSystem, authFailed.Content.ReadAsStringAsync().Result);
                    c.Info.Should().BeNull();
                    c.Token.Should().BeNull();
                }
            }
        }

        [Test]
        public void basic_authentication_on_a_created_user()
        {
            var user = TestHelper.StObjMap.Default.Obtain<UserTable>();
            var basic = TestHelper.StObjMap.Default.Obtain<IBasicAuthenticationProvider>();
            using (var ctx = new SqlStandardCallContext())
            using (var server = new AuthServer(new WebFrontAuthMiddlewareOptions()))
            {
                string userName = Guid.NewGuid().ToString();
                int idUser = user.CreateUser(ctx, 1, userName);
                basic.CreateOrUpdatePasswordUser(ctx, 1, idUser, "pass");

                {
                    HttpResponseMessage authBasic = server.Client.Post(basicLoginUri, new JObject(new JProperty("userName", userName), new JProperty("password", "pass")).ToString());
                    var c = RefreshResponse.Parse(server.TypeSystem, authBasic.Content.ReadAsStringAsync().Result);
                    c.Info.Level.Should().Be(AuthLevel.Normal);
                    c.Info.User.UserId.Should().Be(idUser);
                    c.Info.User.Providers.Select(p => p.Name).ShouldBeEquivalentTo(new[] { "Basic" });
                    c.Token.Should().NotBeNullOrWhiteSpace();
                }

                {
                    HttpResponseMessage authFailed = server.Client.Post(basicLoginUri, new JObject(new JProperty("userName", userName), new JProperty("password", "failed")).ToString());
                    var c = RefreshResponse.Parse(server.TypeSystem, authFailed.Content.ReadAsStringAsync().Result);
                    c.Info.Should().BeNull();
                    c.Token.Should().BeNull();
                }
            }
        }
    }

}
