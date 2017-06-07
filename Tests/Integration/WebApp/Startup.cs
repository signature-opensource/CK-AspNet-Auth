using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using CK.Auth;
using CK.AspNet.Auth;
using CK.DB.AspNet.Auth;
using CK.AspNet;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;

namespace WebApp
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication();
            services.AddDefaultStObjMap("WebApp.Tests.Generated");
            services.AddSingleton<IAuthenticationTypeSystem, StdAuthenticationTypeSystem>();
            services.AddSingleton<WebFrontAuthService, SqlWebFrontAuthService>();
        }

        class OidcEventHandler : OpenIdConnectEvents
        {
            public override Task TicketReceived( TicketReceivedContext context )
            {
                var authService = context.HttpContext.RequestServices.GetRequiredService<WebFrontAuthService>();
                return authService.HandleRemoteAuthentication( context );
            }
        }

        class OAuthEventHandler : OAuthEvents
        {
            public override Task TicketReceived( TicketReceivedContext context )
            {
                var authService = context.HttpContext.RequestServices.GetRequiredService<WebFrontAuthService>();
                return authService.HandleRemoteAuthentication( context );
            }
        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole();

            app.UseDeveloperExceptionPage();
            app.UseRequestMonitor( new RequestMonitorMiddlewareOptions() );

            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
            var oidcOptions = new OpenIdConnectOptions
            {
                AuthenticationScheme = "oidc",
                SignInScheme = "WebFrontAuth",
                AutomaticChallenge = false,
                Authority = "http://localhost:5000",
                RequireHttpsMetadata = false,
                Events = new OidcEventHandler(),
                ClientId = "WebApp",
                ClientSecret = "WebApp.Secret"
            };
            app.UseOpenIdConnectAuthentication( oidcOptions );

            app.UseGoogleAuthentication( new GoogleOptions
            {
                AuthenticationScheme = "Google",
                SignInScheme = "WebFrontAuth",
                ClientId = "1012618945754-fi8rm641pdegaler2paqgto94gkpp9du.apps.googleusercontent.com",
                ClientSecret = "vRALhloGWbPs7PJ5LzrTZwkH",
                Events = new OAuthEventHandler()
            } );

            app.UseWebFrontAuth( new WebFrontAuthMiddlewareOptions()
            {
                // WebFrontAuth is the only AuthenticationScheme that is allowed.
                AuthenticationScheme = "WebFrontAuth"
            } );

            //app.UseWebFrontAuthHelper();

            app.UseMiddleware<WebAppMiddleware>();
        }
    }
}
