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

namespace WebApp
{
    public class Startup
    {
        public void ConfigureServices( IServiceCollection services )
        {
            services.AddAuthentication()
                .AddGoogle( "Google", options =>
                {
                    options.SignInScheme = WebFrontAuthOptions.OnlyAuthenticationScheme;
                    options.ClientId = "1012618945754-fi8rm641pdegaler2paqgto94gkpp9du.apps.googleusercontent.com";
                    options.ClientSecret = "vRALhloGWbPs7PJ5LzrTZwkH";
                    options.Events = new OAuthEventHandler();
                } )
                .AddOpenIdConnect( "oidc", options =>
                {
                    options.SignInScheme = WebFrontAuthOptions.OnlyAuthenticationScheme;
                    options.Authority = "http://localhost:5000";
                    options.RequireHttpsMetadata = false;
                    options.ClientId = "WebApp";
                    options.ClientSecret = "WebApp.Secret";
                    options.Events.OnMessageReceived = message =>
                    {
                        var m = message.HttpContext.GetRequestMonitor();
                        using( m.OpenInfo( "Receiving Oidc message" ) )
                        {
                            foreach( var c in message.Request.Headers )
                            {
                                m.Info( $"Header: {c.Key} => {c.Value}" );
                            }
                        }
                        return Task.CompletedTask;
                    };
                    options.Events.OnTicketReceived = c => c.WebFrontAuthRemoteAuthenticateAsync<IUserOidcInfo>( payload =>
                    {
                        payload.SchemeSuffix = "";
                        payload.Sub = c.Principal.FindFirst( "sub" ).Value;
                    } );
                } )
                .AddWebFrontAuth();
            services.AddDefaultStObjMap( "WebApp.Tests.Generated" );
            services.AddSingleton<IWebFrontAuthLoginService, SqlWebFrontAuthLoginService>();
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

        public void Configure( IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory )
        {
            app.UseRequestMonitor();
            app.UseAuthentication();
            app.UseMiddleware<WebAppMiddleware>();
        }
    }
}
