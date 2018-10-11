using CK.Auth;
using CK.Core;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace CK.AspNet.Auth
{
    /// <summary>
    /// Optional service that can handle dynamic scopes.
    /// </summary>
    public interface IWebFrontAuthDynamicScopeProvider : ISingletonAmbientService
    {
        /// <summary>
        /// Called at the start of the external login flow.
        /// </summary>
        /// <param name="m">The monitor to use.</param>
        /// <param name="context">The context.</param>
        /// <returns>Scopes that should be submitted.</returns>
        Task<string[]> GetScopesAsync( IActivityMonitor m, WebFrontAuthStartLoginContext context );

        /// <summary>
        /// Called once the authentication ticket has been received and scopes accepted or rejected by the user.
        /// </summary>
        /// <param name="m">The monitor to use.</param>
        /// <param name="c">Current http context.</param>
        /// <param name="current">Authenticated user information.</param>
        /// <param name="scopes">The scopes that have been accepted.</param>
        /// <returns>The awaitable.</returns>
        Task SetReveivedScopesAsync( IActivityMonitor m, HttpContext c, IAuthenticationInfo current, IReadOnlyList<string> scopes );
    }
}
