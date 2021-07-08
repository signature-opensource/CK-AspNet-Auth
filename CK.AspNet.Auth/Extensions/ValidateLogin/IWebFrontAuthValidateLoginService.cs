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
    /// When this service is available, the login process follows the 3 steps below:
    /// <list type="bullet">
    ///  <item>
    ///  First, the <see cref="IWebFrontAuthLoginService.LoginAsync(HttpContext, IActivityMonitor, string, object, bool)"/> is called
    ///  with a false <c>actualLogin</c> parameter.
    ///  </item>
    ///  <item>
    ///  On success, this <see cref="ValidateLoginAsync(IActivityMonitor, IUserInfo, IWebFrontAuthValidateLoginContext)"/> is called.
    ///  </item>
    ///  <item>
    ///  Then, only if this validation succeeds, the <see cref="IWebFrontAuthLoginService.LoginAsync(HttpContext, IActivityMonitor, string, object, bool)"/>
    ///  is called again with a true <c>actualLogin</c> parameter.
    ///  </item>
    /// </list>
    /// </summary>
    public interface IWebFrontAuthValidateLoginService : ISingletonAutoService
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
