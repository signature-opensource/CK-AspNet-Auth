using CK.Auth;
using System;
using System.Collections.Generic;
using System.Text;

namespace CK.AspNet.Auth
{
    /// <summary>
    /// Immutable capture of the core <see cref="Info"/> along with <see cref="RememberMe"/> option.
    /// This is the information that is stored in the token and the authentication cookie.
    /// </summary>
    public class FrontAuthenticationInfo
    {
        /// <summary>
        /// The authentication information.
        /// </summary>
        public readonly IAuthenticationInfo Info;

        /// <summary>
        /// Whether this authentication info should be memorized or considered
        /// as a transient one.
        /// </summary>
        public readonly bool RememberMe;

        /// <summary>
        /// Initializes a new info.
        /// </summary>
        /// <param name="info">The info.</param>
        /// <param name="rememberMe">The <see cref="RememberMe"/> option.</param>
        public FrontAuthenticationInfo( IAuthenticationInfo info, bool rememberMe )
        {
            Info = info;
            RememberMe = rememberMe;
        }

        /// <summary>
        /// Immutable setter.
        /// </summary>
        /// <param name="info">The new info to consider.</param>
        /// <returns>The new front authentication info.</returns>
        public FrontAuthenticationInfo SetInfo( IAuthenticationInfo info ) => new FrontAuthenticationInfo( info, RememberMe );
    }
}
