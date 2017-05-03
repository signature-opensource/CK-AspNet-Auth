using CK.Auth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using System;

namespace CK.AspNet.Auth
{
    /// <summary>
    /// Options for <see cref="WebFrontAuthMiddleware"/>.
    /// </summary>
    public class WebFrontAuthMiddlewareOptions : AuthenticationOptions, IOptions<WebFrontAuthMiddlewareOptions>
    {
        /// <summary>
        /// The <see cref="WebFrontAuthMiddleware"/> is not designed to be added multiple 
        /// times to an application, hence its name is unique.
        /// </summary>
        public const string OnlyAuthenticationScheme = "WebFrontAuth";

        /// <summary>
        /// Initializes a new instance of <see cref="WebFrontAuthMiddlewareOptions"/>.
        /// </summary>
        public WebFrontAuthMiddlewareOptions()
        {
            AuthenticationScheme = "WebFrontAuth";
            AutomaticAuthenticate = false;
            AutomaticChallenge = false;
        }

        /// <summary>
        /// Gets or sets the entry point (defaults to "/.webfront").
        /// </summary>
        public PathString EntryPath { get; set; } = new PathString( "/.webfront" );

        /// <summary>
        /// Controls how much time the authentication will remain valid 
        /// from the point it is created. 
        /// Defaults to 20 minutes.
        /// This time is extended if <see cref="SlidingExpirationTime"/> is set and
        /// when "<see cref="EntryPath"/>/c/refresh" is called.
        /// </summary>
        public TimeSpan ExpireTimeSpan { get; set; } = TimeSpan.FromMinutes( 20 );

        /// <summary>
        /// Controls how much time the long term, unsafe, authentication information 
        /// will remain valid from the point it is created. 
        /// Defaults to one year.
        /// </summary>
        public TimeSpan? UnsafeExpireTimeSpan { get; set; } = TimeSpan.FromDays( 366 );

        /// <summary>
        /// Gets whether <see cref="UnsafeExpireTimeSpan"/> is not null and 
        /// greater than <see cref="ExpireTimeSpan"/>.
        /// When true a cookie (which <see cref="CookieOptions.Path"/> is "<see cref="EntryPath"/>/c/") 
        /// is used to store the unsafe, but long term, authentication information.
        /// </summary>
        public bool UseLongTermCookie => UnsafeExpireTimeSpan.HasValue && UnsafeExpireTimeSpan > ExpireTimeSpan;

        /// <summary>
        /// Gets whether the authentication cookie (see <see cref="CookieMode"/>) requires or not https.
        /// Note that the long term cookie uses <see cref="CookieOptions.Secure"/> sets to false since it 
        /// does not require any protection.
        /// Defaults to <see cref="CookieSecurePolicy.SameAsRequest"/>.
        /// </summary>
        public CookieSecurePolicy CookieSecurePolicy { get; set; }

        /// <summary>
        /// Gets or sets if and how the cookie is managed to store the authentication information.
        /// Defaults to <see cref="AuthenticationCookieMode.WebFrontPath"/>.
        /// </summary>
        public AuthenticationCookieMode CookieMode { get; set; }

        /// <summary>
        /// If set this will be used by the middleware for data protection (bearer token as well
        /// as authentication cookie).
        /// </summary>
        public IDataProtectionProvider DataProtectionProvider { get; set; }

        /// <summary>
        /// Gets or sets the refresh validation time. 
        /// When set to other than <see cref="TimeSpan.Zero"/> the middleware will re-issue a new token 
        /// (and new authentication cookie if <see cref="CookieMode"/> allows it) with a new expiration time any time it 
        /// processes a "<see cref="EntryPath"/>/c/refresh" request.
        /// This applies to <see cref="IAuthenticationInfo.Expires"/> but not to <see cref="IAuthenticationInfo.CriticalExpires"/>. 
        /// </summary>
        public TimeSpan SlidingExpirationTime { get; set; }

        /// <summary>
        /// Gets or sets the http header name. Defaults to "Authorization".
        /// </summary>
        public string BearerHeaderName { get; set; } = "Authorization";

        /// <summary>
        /// Gets or sets an error handler called whenever an exception occurs.
        /// </summary>
        public Action<Exception> OnError { get; set; } = e => { };

        WebFrontAuthMiddlewareOptions IOptions<WebFrontAuthMiddlewareOptions>.Value => this;

    }
}
