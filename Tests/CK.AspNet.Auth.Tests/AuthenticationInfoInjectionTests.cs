using CK.Auth;
using CK.Testing;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace CK.AspNet.Auth.Tests
{
    [TestFixture]
    public class AuthenticationInfoInjectionTests
    {

        class AuthenticationInfoDependent
        {
            public readonly IAuthenticationInfo AuthInfo;

            public AuthenticationInfoDependent( IAuthenticationInfo auth )
            {
                AuthInfo = auth;
            }
        }

        [Test]
        public async Task IAuthenticationInfo_is_injected_by_AddWebFrontAuth_Async()
        {
            await using var runningServer = await LocalHelper.CreateLocalAuthServerAsync(
                    configureServices: services => services.AddScoped<AuthenticationInfoDependent>(),
                    configureApplication: app =>
                    {
                        app.Use( next =>
                        {
                            return async c =>
                            {
                                await next( c );
                                if( c.Request.Path.StartsWithSegments( "/TestAuth" ) )
                                {
                                    var a = c.RequestServices.GetRequiredService<AuthenticationInfoDependent>();
                                    a.AuthInfo.User.UserName.Should().Be( "Albert" );
                                    c.Response.StatusCode = (int)HttpStatusCode.PaymentRequired;
                                }
                            };
                        } );
                    } );
               
            AuthServerResponse r = await runningServer.Client.LoginViaBasicProviderAsync( "Albert", true );
            runningServer.Client.Token = r.Token;
            var m = await runningServer.Client.GetAsync( "/TestAuth" );
            m.StatusCode.Should().Be( HttpStatusCode.PaymentRequired );
        }
    }

}
