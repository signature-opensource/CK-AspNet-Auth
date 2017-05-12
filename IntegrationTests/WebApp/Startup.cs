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

namespace WebApp
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication();
            services.AddDefaultStObjMap("CK.DB.AspNet.Auth.Generated");
            services.AddSingleton<IAuthenticationTypeSystem, StdAuthenticationTypeSystem>();
            services.AddSingleton<WebFrontAuthService, SqlWebFrontAuthService>();
        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole();

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseWebFrontAuth(new WebFrontAuthMiddlewareOptions());

            app.Run(async (context) =>
            {
                await context.Response.WriteAsync("Hello World!");
            });
        }
    }
}
