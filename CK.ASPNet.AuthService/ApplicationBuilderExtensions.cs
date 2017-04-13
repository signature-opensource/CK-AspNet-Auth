using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Configuration;
using System.Text;
using CK.Auth;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace CK.AspNet.AuthService
{
    public static class ApplicationBuilderExtensions
    {
        /// <summary>
        /// Configures the services collection by adding Authentication middleware.
        /// </summary>
        /// <param name="services">Services collection to configure.</param>
        /// <returns>The services collection.</returns>
        public static IServiceCollection AddWebFrontAuth( this IServiceCollection services )
        {
            services.AddAuthentication();
            services.AddSingleton<IAuthenticationTypeSystem, StdAuthenticationTypeSystem>();
            services.AddSingleton<WebFrontAuthService, WebFrontAuthServiceDB>();
            return services;
        }

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
