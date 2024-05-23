using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CK.Auth;
using CK.Core;
using Microsoft.AspNetCore.Http;

namespace CK.AspNet.Auth.Tests
{
    class ImpersonationForEverybodyService : IWebFrontAuthImpersonationService
    {
        readonly FakeWebFrontLoginService _loginService;

        public ImpersonationForEverybodyService( IWebFrontAuthLoginService loginService )
        {
            _loginService = (FakeWebFrontLoginService)loginService;
        }

        public Task<IUserInfo?> ImpersonateAsync( HttpContext ctx, IActivityMonitor monitor, IAuthenticationInfo info, int userId )
        {
            return Task.FromResult( _loginService.AllUsers.FirstOrDefault( u => u.UserId == userId ) );
        }

        public Task<IUserInfo?> ImpersonateAsync( HttpContext ctx, IActivityMonitor monitor, IAuthenticationInfo info, string userName )
        {
            return Task.FromResult( _loginService.AllUsers.FirstOrDefault( u => u.UserName == userName ) );
        }
    }
}
