using CK.Auth;
using CK.Core;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace CK.AspNet.Auth
{
    /// <summary>
    /// Optional service that, when registered, offers login validations.
    /// </summary>
    public interface IWebFrontAuthValidateLoginService
    {
        /// <summary>
        /// Called for each login. Any error set on the <paramref name="context"/> cancels the login.
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="loggedInUser">The logged in user.</param>
        /// <param name="context">Validation context.</param>
        /// <returns>The awaitable.</returns>
        Task ValidateLoginAsync( IActivityMonitor monitor, IUserInfo loggedInUser, IWebFrontAuthValidateLoginContext context );
    }
}
