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
using CK.Core;
using CK.DB.User.UserOidc;
using CK.DB.User.UserGoogle;

namespace WebApp
{
    public class Startup
    {
        public void ConfigureServices( IServiceCollection services )
        {
            services.AddAuthentication();
            services.AddDefaultStObjMap( "WebApp.Tests.Generated" );
            services.AddSingleton<IAuthenticationTypeSystem, StdAuthenticationTypeSystem>();
            services.AddSingleton<IWebFrontAuthLoginService, SqlWebFrontAuthLoginService>();
            services.AddSingleton<WebFrontAuthService>();
        }

        class OidcEventHandler : OpenIdConnectEvents
        {
            public override Task TicketReceived( TicketReceivedContext c )
            {
                var authService = c.HttpContext.RequestServices.GetRequiredService<WebFrontAuthService>();
                return authService.HandleRemoteAuthentication<IUserOidcInfo>( c, payload =>
                {
                    payload.SchemeSuffix = "";
                    payload.Sub = c.Principal.FindFirst( "sub" ).Value;
                } );
            }
        }

        class OAuthEventHandler : OAuthEvents
        {
            public override Task TicketReceived( TicketReceivedContext c )
            {
                var authService = c.HttpContext.RequestServices.GetRequiredService<WebFrontAuthService>();
                return authService.HandleRemoteAuthentication<IUserGoogleInfo>( c, payload =>
                {
                    payload.GoogleAccountId = c.Principal.FindFirst( "AccountId" ).Value;
                } );
            }
        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole();

            if( env.IsDevelopment() )
            {
                app.UseDeveloperExceptionPage();
            }
            app.UseRequestMonitor( new RequestMonitorMiddlewareOptions()
            {
                // In release, we silently catch and log any error.
                SwallowErrors = !env.IsDevelopment()
            } );

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
                AuthenticationScheme = "WebFrontAuth",
                
            } );


            app.UseMiddleware<WebAppMiddleware>();
        }
    }
}
