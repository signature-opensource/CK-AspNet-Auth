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
    /// Interface to the backend login service.
    /// </summary>
    public interface IWebFrontAuthLoginService
    {
        /// <summary>
        /// Gets whether <see cref="BasicLoginAsync"/> is supported.
        /// </summary>
        bool HasBasicLogin { get; }

        /// <summary>
        /// Gets the existing providers's name.
        /// </summary>
        IReadOnlyList<string> Providers { get; }

        /// <summary>
        /// Attempts to login. <see cref="HasBasicLogin"/> must be true for this
        /// to be called. Must never return null. 
        /// </summary>
        /// <param name="ctx">Current Http context.</param>
        /// <param name="monitor">The activity monitor to use.</param>
        /// <param name="userName">The user name.</param>
        /// <param name="password">The password.</param>
        /// <param name="actualLogin">
        /// Set it to false to avoid login side-effect (such as updating the LastLoginTime) on success:
        /// only checks are done.
        /// </param>
        /// <returns>A non null <see cref="UserLoginResult"/>.</returns>
        Task<UserLoginResult> BasicLoginAsync( HttpContext ctx, IActivityMonitor monitor, string userName, string password, bool actualLogin = true );

        /// <summary>
        /// Creates a payload object for a given scheme that can be used to 
        /// call <see cref="LoginAsync"/>.
        /// </summary>
        /// <param name="ctx">Current Http context.</param>
        /// <param name="monitor">The activity monitor to use.</param>
        /// <param name="scheme">The login scheme (either the provider name to use or starts with the provider name and a dot).</param>
        /// <returns>A new, empty, provider dependent login payload.</returns>
        object CreatePayload( HttpContext ctx, IActivityMonitor monitor, string scheme );

        /// <summary>
        /// Attempts to login a user using an existing provider.
        /// The provider derived from the scheme must exist and the payload must be compatible 
        /// otherwise an <see cref="ArgumentException"/> is thrown.
        /// Must never return null. 
        /// </summary>
        /// <param name="ctx">Current Http context.</param>
        /// <param name="monitor">The activity monitor to use.</param>
        /// <param name="scheme">The login scheme (either the provider name to use or starts with the provider name and a dotted suffix).</param>
        /// <param name="payload">The provider dependent login payload.</param>
        /// <param name="actualLogin">
        /// Set it to false to avoid login side-effect (such as updating the LastLoginTime) on success:
        /// only checks are done.
        /// </param>
        /// <returns>A non null <see cref="UserLoginResult"/>.</returns>
        Task<UserLoginResult> LoginAsync( HttpContext ctx, IActivityMonitor monitor, string scheme, object payload, bool actualLogin = true );
    }
}
