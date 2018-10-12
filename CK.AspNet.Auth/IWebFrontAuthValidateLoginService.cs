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
    /// Optional service that, when registered, enables login validations.
    /// </summary>
    /// <remarks>
    /// This reuses the interface marker from CK.Auth since we do not depend on CK.StObj.Model here.
    /// </remarks>
    public interface IWebFrontAuthValidateLoginService : ISingletonAmbientService
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
