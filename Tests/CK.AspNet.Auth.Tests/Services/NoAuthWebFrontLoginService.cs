using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CK.Auth;
using Microsoft.AspNetCore.Http;
using CK.Core;

namespace CK.AspNet.Auth.Tests
{
    class NoAuthWebFrontLoginService : IWebFrontAuthLoginService
    {
        public NoAuthWebFrontLoginService( IAuthenticationTypeSystem typeSystem )
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
    }
}
