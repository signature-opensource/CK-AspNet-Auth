using CK.AspNet.Auth;
using CK.Auth;
using Microsoft.AspNetCore.Authentication;
using System;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Offers support for WebFrontAuth on <see cref="AuthenticationBuilder"/>.
    /// </summary>
    public static class WebFrontAuthExtensions
    {
        /// <summary>
        /// Adds the WebFrontAuth authentication services without options configuration.
        /// </summary>
        /// <param name="this">This Authentication builder.</param>
        /// <returns>Authentication builder to enable fluent syntax.</returns>
        public static AuthenticationBuilder AddWebFrontAuth( this AuthenticationBuilder @this )
        {
            return @this.AddWebFrontAuth( null );
        }

        /// <summary>
        /// Adds the WebFrontAuth authentication services with options configuration.
        /// </summary>
        /// <param name="this">This Authentication builder.</param>
        /// <param name="configure">Configuration action.</param>
        /// <returns>Authentication builder to enable fluent syntax.</returns>
        public static AuthenticationBuilder AddWebFrontAuth( this AuthenticationBuilder @this, Action<WebFrontAuthOptions> configure )
        {
            @this.Services.AddSingleton<WebFrontAuthService>();
            @this.AddScheme<WebFrontAuthOptions, WebFrontAuthHandler>( WebFrontAuthOptions.OnlyAuthenticationScheme, "Web Front Authentication", configure );
            return @this;
        }
    }
}
