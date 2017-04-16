using CK.DB.Auth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CK.DB.AspNet.Auth.Tests
{
    public class MockAuthUser : IUserAuthInfo
    {
        public int UserId { get; set; }

        public string UserName { get; set; }

        IReadOnlyList<UserAuthProviderInfo> IUserAuthInfo.Providers => Providers;

        public List<UserAuthProviderInfo> Providers { get; } = new List<UserAuthProviderInfo>();
    }

}
