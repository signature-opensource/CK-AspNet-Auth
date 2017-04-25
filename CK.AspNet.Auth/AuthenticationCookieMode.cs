using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Text;

namespace CK.AspNet.Auth
{

    /// <summary>
    /// Describes the how the authentication cookie is managed.
    /// </summary>
    public enum AuthenticationCookieMode
    {
        /// <summary>
        /// The  authentication cookie <see cref="CookieOptions.Path"/> is set on the <see cref="WebFrontAuthMiddlewareOptions.EntryPath"/>/c/.
        /// This is the default mode.
        /// </summary>
        WebFrontPath = 0,

        /// <summary>
        /// The authentication cookie <see cref="CookieOptions.Path"/> is set on the root path: 
        /// this enables the <see cref="WebFrontAuthMiddleware"/> to act as a standard Cookie authentication 
        /// middleware (applies to classical, server rendered, web site).
        /// </summary>
        RootPath = 1,

        /// <summary>
        /// No authentication cookie is set (and no challenge is done).
        /// </summary>
        None = 2

    }
}
