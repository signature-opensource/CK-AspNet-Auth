using CK.AspNet.Auth;
using CK.Auth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection.Extensions;
using System;
using System.Linq;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Offers support for WebFrontAuth on <see cref="AuthenticationBuilder"/>.
    /// </summary>
    public static class WebFrontAuthExtensions
    {
        /// <summary>
        /// Adds the WebFrontAuth authentication services with options configuration.
        /// This registers <see cref="IAuthenticationInfo"/> as a scoped dependency.
        /// That relies on the <see cref="CK.AspNet.ScopedHttpContext"/> that MUST be registered.
        /// </summary>
        /// <param name="this">This Authentication builder.</param>
        /// <param name="configure">Optional configuration action.</param>
        /// <returns>This authentication builder to enable fluent syntax.</returns>
        public static AuthenticationBuilder AddWebFrontAuth( this AuthenticationBuilder @this, Action<WebFrontAuthOptions>? configure = null )
        {
            @this.Services.AddSingleton<WebFrontAuthService>();
            @this.AddScheme<WebFrontAuthOptions, WebFrontAuthHandler>( WebFrontAuthOptions.OnlyAuthenticationScheme, "Web Front Authentication", configure );
            @this.Services.TryAddScoped( sp => sp.GetRequiredService<CK.AspNet.ScopedHttpContext>().HttpContext.GetAuthenticationInfo() );
            return @this;
        }
    }
}
