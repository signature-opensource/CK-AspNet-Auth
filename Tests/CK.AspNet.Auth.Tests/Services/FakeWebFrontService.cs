using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CK.Auth;
using Microsoft.AspNetCore.Http;

namespace CK.AspNet.Auth.Tests
{
    class FakeWebFrontService : WebFrontAuthService
    {
        readonly List<IUserInfo> _users;

        public FakeWebFrontService(IAuthenticationTypeSystem typeSystem)
            : base(typeSystem)
        {
            _users = new List<IUserInfo>();
            // Albert is registered in Basic.
            _users.Add(typeSystem.UserInfo.Create(1, "System"));
            _users.Add(typeSystem.UserInfo.Create(2, "Albert", new[] { new StdUserProviderInfo("Basic", DateTime.MinValue) }));
            _users.Add(typeSystem.UserInfo.Create(3, "Robert"));
            // Hubert is registered in Google.
            _users.Add(typeSystem.UserInfo.Create(3, "Hubert", new[] { new StdUserProviderInfo("Google", DateTime.MinValue) }));
        }

        public override bool HasBasicLogin => true;

        public override IReadOnlyList<string> Providers => new string[] { "Basic" };

        public override Task<IUserInfo> BasicLoginAsync( HttpContext ctx, string userName, string password)
        {
            IUserInfo u = null;
            if (password == "success")
            {
                u = _users.FirstOrDefault(i => i.UserName == userName);
                if( u != null && u.Providers.Any( p => p.Name == "Basic" ))
                {
                    _users.Remove(u);
                    u = AuthenticationTypeSystem.UserInfo.Create(u.UserId, u.UserName, new[] { new StdUserProviderInfo("Basic", DateTime.UtcNow) });
                    _users.Add(u);
                }
            }
            return Task.FromResult(u);
        }

        public override Task<IUserInfo> LoginAsync(HttpContext ctx, string providerName, object payload)
        {
            throw new NotImplementedException();
        }
    }
}
