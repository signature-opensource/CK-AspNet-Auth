using CK.Auth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace CK.AspNet.Auth
{
    /// <summary>
    /// Options for <see cref="WebFrontAuthService"/>.
    /// </summary>
    public class WebFrontAuthOptions : AuthenticationSchemeOptions
    {
        static readonly PathString _entryPath = new PathString( "/.webfront" );

        /// <summary>
        /// The <see cref="WebFrontAuthService"/> is not designed to be added multiple 
        /// times to an application, hence its name is unique.
        /// </summary>
        public const string OnlyAuthenticationScheme = "WebFrontAuth";

        /// <summary>
        /// Gets the entry point: "/.webfront".
        /// </summary>
        public PathString EntryPath => _entryPath;

        /// <summary>
        /// Controls how much time the authentication will remain valid 
        /// from the point it is created. 
        /// Defaults to 20 minutes.
        /// This time is extended if <see cref="SlidingExpirationTime"/> is set and
        /// when "<see cref="EntryPath"/>/c/refresh" is called.
        /// This configuration can be changed dynamically: modifying the configuration will take the
        /// new value into account.
        /// </summary>
        public TimeSpan ExpireTimeSpan { get; set; } = TimeSpan.FromMinutes( 20 );

        /// <summary>
        /// Controls how much time the long term, unsafe, authentication information 
        /// will remain valid from the point it is created. 
        /// Defaults to one year.
        /// This configuration can be changed dynamically.
        /// </summary>
        public TimeSpan? UnsafeExpireTimeSpan { get; set; } = TimeSpan.FromDays( 366 );

        /// <summary>
        /// Gets whether <see cref="UnsafeExpireTimeSpan"/> is not null, greater than <see cref="ExpireTimeSpan"/>,
        /// and <see cref="CookieMode"/> is not <see cref="AuthenticationCookieMode.None"/>.
        /// When true a long-lived cookie is used to store the unsafe, but long term, authentication information.
        /// Its <see cref="CookieOptions.Path"/> depends on <see cref="CookieMode"/>.
        /// </summary>
        public bool UseLongTermCookie => UnsafeExpireTimeSpan.HasValue 
                                            && UnsafeExpireTimeSpan > ExpireTimeSpan 
                                            && CookieMode != AuthenticationCookieMode.None;

        /// <summary>
        /// Gets whether the authentication cookie (see <see cref="CookieMode"/>) requires or not https.
        /// Note that the long term cookie uses <see cref="CookieOptions.Secure"/> sets to false since it 
        /// does not require any protection.
        /// Defaults to <see cref="CookieSecurePolicy.SameAsRequest"/>.
        /// This can not be changed dynamically.
        /// </summary>
        public CookieSecurePolicy CookieSecurePolicy { get; set; }

        /// <summary>
        /// Gets or sets if and how cookies are managed to store the authentication information.
        /// <para>
        /// Defaults to <see cref="AuthenticationCookieMode.WebFrontPath"/>.
        /// </para>
        /// <para>
        /// Setting it to <see cref="AuthenticationCookieMode.RootPath"/> should NOT BE used for 
        /// professional development: this mode, that is the same as the standard Cookie ASP.Net authentication,
        /// works only for standard and classical Web application. 
        /// </para>
        /// <para>
        /// Setting it to <see cref="AuthenticationCookieMode.None"/> disables all cookies: client apps
        /// are no more "F5 resilient", this can be used for pure API implementations.
        /// </para>
        /// <para>
        /// This can not be changed dynamically.
        /// </para>
        /// </summary>
        public AuthenticationCookieMode CookieMode { get; set; }

        /// <summary>
        /// Gets or sets a list of available schemes returned for information from '/c/refresh' endpoint 
        /// when 'schemes' appears in the query string.
        /// <para>
        /// Defaults to null: schemes are the same as <see cref="IWebFrontAuthLoginService.Providers"/>
        /// when this is null or empty.
        /// </para>
        /// <para>
        /// When not null (or empty), this list takes precedence over the login service's providers: all supported 
        /// schemes must be declared here (and unwanted ones must not appear).
        /// </para>
        /// <para>
        /// This list does not forbid user login to non listed schemes, this is intended only for applications
        /// to communicate with the user.
        /// </para>
        /// <para>
        /// This configuration can be changed dynamically: modifying the configuration will take the
        /// new schemes into account.
        /// </para>
        /// </summary>
        public List<string> AvailableSchemes { get; set; }

        /// <summary>
        /// Gets or sets the refresh validation time. 
        /// When set to other than <see cref="TimeSpan.Zero"/> the middleware will re-issue a new token 
        /// (and new authentication cookie if <see cref="CookieMode"/> allows it) with a new expiration time any time it 
        /// processes a "<see cref="EntryPath"/>/c/refresh" request.
        /// This applies to <see cref="IAuthenticationInfo.Expires"/> but not to <see cref="IAuthenticationInfo.CriticalExpires"/>. 
        /// This configuration can be changed dynamically: modifying the configuration will take the
        /// new value into account.
        /// </summary>
        public TimeSpan SlidingExpirationTime { get; set; }

        /// <summary>
        /// Gets or sets the http header name. Defaults to "Authorization".
        /// This can not be changed dynamically.
        /// </summary>
        public string BearerHeaderName { get; set; } = "Authorization";
       

    }
}
