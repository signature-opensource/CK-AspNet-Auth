using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CK.Auth;
using CK.Core;

namespace CK.AspNet.Auth.Tests
{
    class NoBasicWebFrontService : WebFrontAuthService
    {
        public NoBasicWebFrontService(IAuthenticationTypeSystem typeSystem)
            : base(typeSystem)
        {
        }

        public override bool HasBasicLogin => false;

        public override IReadOnlyList<string> Providers => new string[0];

        public override Task<IUserInfo> BasicLoginAsync(string userName, string password)
        {
            throw new NotSupportedException();
        }

        public override Task<IUserInfo> LoginAsync(string providerName, object payload)
        {
            throw new NotSupportedException();
        }
    }
}
