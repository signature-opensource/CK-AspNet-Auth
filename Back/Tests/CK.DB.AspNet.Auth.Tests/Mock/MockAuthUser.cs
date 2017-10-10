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

        IReadOnlyList<UserAuthSchemeInfo> IUserAuthInfo.Schemes => Schemes;

        public List<UserAuthSchemeInfo> Schemes { get; } = new List<UserAuthSchemeInfo>();
    }

}
