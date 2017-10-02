using CK.Auth;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using System;

namespace CK.AspNet.Auth
{

    /// <summary>
    /// Adds classical helper to <see cref="IApplicationBuilder"/>.
    /// </summary>
    public static class CKAspNetAuthApplicationBuilderExtensions
    {
        /// <summary>
        /// Configures the pipe line with the <see cref="WebFrontAuthMiddleware"/>.
        /// </summary>
        /// <param name="app">The application builder.</param>
        /// <param name="options">The options.</param>
        /// <returns>The application builder.</returns>
        [Obsolete( "Use AddWebFrontAuth on AuthenticationBuilder", true )]
        public static IApplicationBuilder UseWebFrontAuth( this IApplicationBuilder app, WebFrontAuthOptions options )
        {
            throw new NotSupportedException( "Use AddWebFrontAuth on AuthenticationBuilder" );
        }

    }
}
