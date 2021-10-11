using CK.Auth;
using System;
using System.Collections.Generic;
using System.Text;

namespace CK.AspNet.Auth
{
    /// <summary>
    /// Immutable capture of the core <see cref="Info"/> along with <see cref="RememberMe"/> option.
    /// This is the information that is stored in the token and the authentication cookie.
    /// <para>
    /// It's a reference type since it is stored in the HttpContext's Items (a struct would be boxed 99% of the times).
    /// </para>
    /// </summary>
    public sealed class FrontAuthenticationInfo
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
        /// <returns>The new front authentication info (or this).</returns>
        public FrontAuthenticationInfo SetInfo( IAuthenticationInfo info ) => info == Info ? this : new FrontAuthenticationInfo( info, RememberMe );

        /// <summary>
        /// Immutable setter.
        /// Ensures that <see cref="IAuthenticationInfo.Level"/> is <see cref="AuthLevel.Unsafe"/>.
        /// The user identifier and name is available (but at the unsafe level), of course, this preserves the device identifier
        /// and the <see cref="RememberMe"/> flag are preserved. This is a kind of "soft logout".
        /// </summary>
        /// <returns>The new front authentication info (or this).</returns>
        public FrontAuthenticationInfo SetUnsafeLevel() => Info.Level <= AuthLevel.Unsafe
                                                            ? this
                                                            : new FrontAuthenticationInfo( Info.SetExpires( null ), RememberMe );

        /// <summary>
        /// Immutable setter.
        /// </summary>
        /// <param name="rememberMe">The new remember me.</param>
        /// <returns>The new front authentication info (or this).</returns>
        public FrontAuthenticationInfo SetRememberMe( bool rememberMe ) => rememberMe == RememberMe ? this : new FrontAuthenticationInfo( Info, rememberMe );
    }
}
