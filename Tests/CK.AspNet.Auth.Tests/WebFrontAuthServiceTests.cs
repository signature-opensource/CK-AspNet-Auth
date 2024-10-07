using CK.Testing;
using NUnit.Framework;
using System.Diagnostics;
using System.Threading.Tasks;

namespace CK.AspNet.Auth.Tests;

[TestFixture]
public class WebFrontAuthServiceTests
{
    /// <summary>
    /// Calling ChallengeAsync leads to WebFrontAuthService.HandleAuthenticate that sets HttpContext.User principal
    /// from the current IAuthenticationInfo: the actual test is in LocalTestHelper inline middleware.
    /// </summary>
    [Test]
    public async Task calling_challenge_Async()
    {
        await using var runningServer = await LocalHelper.CreateLocalAuthServerAsync();

        // Login: the 2 cookies are set on .webFront/c/ path.
        var login = await runningServer.Client.AuthenticationBasicLoginAsync( "Albert", true );
        Debug.Assert( login.Info != null );
        await runningServer.Client.GetAsync( "/CallChallengeAsync" );
    }
}
