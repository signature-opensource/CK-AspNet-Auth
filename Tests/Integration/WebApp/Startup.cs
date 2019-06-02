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
using Microsoft.AspNetCore.Authentication.Google;
using System.Security.Claims;

namespace WebApp
{
    public class Startup
    {
        public void ConfigureServices( IServiceCollection services )
        {
            services.AddAuthentication( WebFrontAuthOptions.OnlyAuthenticationScheme )
                .AddGoogle( "Google", options =>
                {
                    options.ClientId = "1012618945754-fi8rm641pdegaler2paqgto94gkpp9du.apps.googleusercontent.com";
                    options.ClientSecret = "vRALhloGWbPs7PJ5LzrTZwkH";
                    options.Events = new OAuthEventHandler();
                } )
                .AddOpenIdConnect( "oidc", options =>
                {
                    options.Authority = "http://localhost:5000";
                    options.RequireHttpsMetadata = false;
                    options.ClientId = "WebApp";
                    options.ClientSecret = "WebApp.Secret";
                    options.Events.OnTicketReceived = c => c.WebFrontAuthRemoteAuthenticateAsync<IUserOidcInfo>( payload =>
                    {
                        payload.SchemeSuffix = "";
                        // Instead of "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"
                        // Use standard System.Security.Claims.ClaimTypes.
                        payload.Sub = c.Principal.FindFirst( ClaimTypes.NameIdentifier ).Value;
                    } );
                } )
                .AddWebFrontAuth();
            services.AddCKDatabase( "CK.StObj.AutoAssembly" );
            //services.AddSingleton<IWebFrontAuthLoginService, SqlWebFrontAuthLoginService>();
            //services.AddSingleton<IWebFrontAuthAutoCreateAccountService,AutoCreateAccountService>();
        }

        class OAuthEventHandler : OAuthEvents
        {
            public override Task TicketReceived( TicketReceivedContext c )
            {
                var authService = c.HttpContext.RequestServices.GetRequiredService<WebFrontAuthService>();
                return authService.HandleRemoteAuthentication<IUserGoogleInfo>( c, payload =>
                {
                    payload.GoogleAccountId = c.Principal.FindFirst( ClaimTypes.NameIdentifier ).Value;
                } );
            }
        }

        public void Configure( IApplicationBuilder app )
        {
            app.UseRequestMonitor();
            app.UseAuthentication();
            app.UseMiddleware<WebAppMiddleware>();
        }
    }
}
