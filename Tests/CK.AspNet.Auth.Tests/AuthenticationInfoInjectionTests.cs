using CK.Auth;
using CK.Testing;
using Shouldly;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using System.Net;
using System.Threading.Tasks;

namespace CK.AspNet.Auth.Tests;

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
                                a.AuthInfo.User.UserName.ShouldBe( "Albert" );
                                c.Response.StatusCode = (int)HttpStatusCode.PaymentRequired;
                            }
                        };
                    } );
                } );

        AuthServerResponse r = await runningServer.Client.AuthenticationBasicLoginAsync( "Albert", true );
        runningServer.Client.Token = r.Token;
        var m = await runningServer.Client.GetAsync( "/TestAuth" );
        m.StatusCode.ShouldBe( HttpStatusCode.PaymentRequired );
    }
}
