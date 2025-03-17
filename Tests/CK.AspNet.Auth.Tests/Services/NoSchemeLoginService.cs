using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using CK.Auth;
using Microsoft.AspNetCore.Http;
using CK.Core;

namespace CK.AspNet.Auth.Tests;

class NoSchemeLoginService : IWebFrontAuthLoginService
{
    public NoSchemeLoginService( IAuthenticationTypeSystem typeSystem )
    {
    }

    public bool HasBasicLogin => false;

    public IReadOnlyList<string> Providers => new string[0];

    public Task<UserLoginResult> BasicLoginAsync( HttpContext ctx, IActivityMonitor monitor, string userName, string password, bool actualLogin )
    {
        throw new NotSupportedException();
    }

    public object CreatePayload( HttpContext ctx, IActivityMonitor monitor, string scheme )
    {
        throw new NotSupportedException();
    }

    public Task<UserLoginResult> LoginAsync( HttpContext ctx, IActivityMonitor monitor, string providerName, object payload, bool actualLogin )
    {
        throw new NotSupportedException();
    }

    public Task<IAuthenticationInfo> RefreshAuthenticationInfoAsync( HttpContext ctx, IActivityMonitor monitor, IAuthenticationInfo current, DateTime newExpires )
    {
        throw new NotSupportedException();
    }
}
