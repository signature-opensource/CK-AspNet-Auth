using CK.AspNet.Auth;
using CK.DB.Actor;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace WebApp
{
    public class SignInHandlerService : IWebFrontAuthSignInService
    {
        readonly UserTable _user;

        public SignInHandlerService( UserTable user )
        {
            _user = user;
        }
        public Task SignIn( WebFrontAuthSignInContext context )
        {
            int userId = context.InitialAuthentication.User.UserId;
            if( userId == 0 )
            {
            }
            return Task.CompletedTask;
        }
    }
}
