using CK.Auth;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace CK.AspNet.Auth
{
    public static class ApplicationBuilderExtensions
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
