using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace CK.AspNet.Auth
{
    public interface IWebFrontAuthSignInService
    {
        Task SignIn( WebFrontAuthSignInContext context );
    }
}
