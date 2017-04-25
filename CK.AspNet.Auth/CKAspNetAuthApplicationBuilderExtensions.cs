using CK.Auth;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

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
        public static IApplicationBuilder UseWebFrontAuth( this IApplicationBuilder app, WebFrontAuthMiddlewareOptions options )
        {
            return app.UseMiddleware<WebFrontAuthMiddleware>( options );
        }

    }
}
