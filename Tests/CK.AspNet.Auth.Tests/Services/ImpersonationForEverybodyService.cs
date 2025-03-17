using System.Linq;
using System.Threading.Tasks;
using CK.Auth;
using CK.Testing;
using CK.Core;
using Microsoft.AspNetCore.Http;

namespace CK.AspNet.Auth.Tests;


class ImpersonationForEverybodyService : IWebFrontAuthImpersonationService
{
    // We cannot use the IUserInfoProvider here since it only handles user identifier and not user name.
    readonly FakeWebFrontAuthLoginService _loginService;

    public ImpersonationForEverybodyService( FakeWebFrontAuthLoginService loginService )
    {
        _loginService = loginService;
    }

    public Task<IUserInfo?> ImpersonateAsync( HttpContext ctx, IActivityMonitor monitor, IAuthenticationInfo info, int userId )
    {
        return Task.FromResult( _loginService.UserDatabase.AllUsers.FirstOrDefault( u => u.UserId == userId ) );
    }

    public Task<IUserInfo?> ImpersonateAsync( HttpContext ctx, IActivityMonitor monitor, IAuthenticationInfo info, string userName )
    {
        Throw.CheckNotNullArgument( userName );
        return Task.FromResult( _loginService.UserDatabase.AllUsers.FirstOrDefault( u => u.UserName == userName ) );
    }
}
