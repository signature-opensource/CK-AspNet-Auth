using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CK.Auth;
using Microsoft.AspNetCore.Http;

namespace CK.AspNet.Auth.Tests
{
    class NoAuthWebFrontService : WebFrontAuthService
    {
        public NoAuthWebFrontService(IAuthenticationTypeSystem typeSystem)
            : base(typeSystem)
        {
        }

        public override bool HasBasicLogin => false;

        public override IReadOnlyList<string> Providers => new string[0];

        public override Task<IUserInfo> BasicLoginAsync(HttpContext ctx, string userName, string password)
        {
            throw new NotSupportedException();
        }

        public override Task<IUserInfo> LoginAsync(HttpContext ctx, string providerName, object payload)
        {
            throw new NotSupportedException();
        }
    }
}
