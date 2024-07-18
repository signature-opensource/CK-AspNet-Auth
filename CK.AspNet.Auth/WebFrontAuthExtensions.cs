using CK.AspNet;
using CK.AspNet.Auth;
using CK.Auth;
using CK.Core;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Cors.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Offers support for WebFrontAuth on <see cref="AuthenticationBuilder"/>.
    /// </summary>
    public static class WebFrontAuthExtensions
    {
        /// <summary>
        /// Idempotent registration of the <see cref="WebFrontAuthService"/>, <see cref="IAuthenticationInfo"/> and <see cref="AuthenticationBuilder"/>
        /// with the <see cref="WebFrontAuthOptions.OnlyAuthenticationScheme"/>.
        /// <para>
        /// When called more than once, all <paramref name="authOptions"/> are applied to the final <see cref="WebFrontAuthOptions"/>.
        /// </para>
        /// </summary>
        /// <param name="builder">This builder.</param>
        /// <param name="authOptions">Optional option configuration.</param>
        /// <returns>This builder.</returns>
        public static WebApplicationBuilder AddWebFrontAuth( this WebApplicationBuilder builder,
                                                             Action<WebFrontAuthOptions>? authOptions = null )
        {
            var props = ((IHostApplicationBuilder)builder).Properties;
            if( props.TryAdd( typeof( WebFrontAuthExtensions ), typeof( WebFrontAuthExtensions ) ) )
            {
                builder.Services.AddSingleton<WebFrontAuthService>();
                builder.Services.AddScoped( sp => sp.GetRequiredService<ScopedHttpContext>().HttpContext.GetAuthenticationInfo() );
                var authBuilder = builder.Services.AddAuthentication( WebFrontAuthOptions.OnlyAuthenticationScheme );
                authBuilder.AddScheme<WebFrontAuthOptions, WebFrontAuthHandler>( WebFrontAuthOptions.OnlyAuthenticationScheme, "Web Front Authentication", authOptions );
                builder.AppendApplicationBuilder( app => app.UseAuthentication() );
            }
            else if( authOptions != null )
            {
                // Already called. If an option configurator is present, register the new one.
                // The OptionsFactory<T> will call all the registered IConfigureOptions<T>.
                var configurator = new ConfigureNamedOptions<WebFrontAuthOptions>( WebFrontAuthOptions.OnlyAuthenticationScheme, authOptions );
                builder.Services.AddSingleton<IConfigureOptions<WebFrontAuthOptions>>( configurator );
            }
            return builder;
        }

        /// <summary>
        /// Add dangerous Cors support: this allows all orgigins, methods, headers AND supports credential.
        /// This is unfortunately required in some testing scenario but should NEVER be used in production.
        /// <para>
        /// This method, just like <see cref="AddCors(WebApplicationBuilder, string)"/> and <see cref="AddCors(WebApplicationBuilder, Action{CorsPolicyBuilder})"/>
        /// can be called multiple times: the last wins.
        /// </para>
        /// </summary>
        /// <param name="builder">This builder.</param>
        /// <returns>This builder.</returns>
        public static WebApplicationBuilder AddUnsafeAllowAllCors( this WebApplicationBuilder builder )
        {
            return AddCors( builder, CorsAllowAllBuilder );

            static void CorsAllowAllBuilder( CorsPolicyBuilder o )
            {
                o.AllowAnyMethod().AllowCredentials().AllowAnyHeader().SetIsOriginAllowed( _ => true );
            }
        }

        /// <summary>
        /// Add Cors support for a single policy.
        /// <para>
        /// This method, just like <see cref="AddCors(WebApplicationBuilder, string)"/> and <see cref="AddUnsafeAllowAllCors(WebApplicationBuilder)"/>
        /// can be called multiple times: the last wins.
        /// </para>
        /// </summary>
        /// <param name="builder">This builder.</param>
        /// <param name="policyBuilder">The cors policy builder.</param>
        /// <returns></returns>
        public static WebApplicationBuilder AddCors( this WebApplicationBuilder builder,
                                                     Action<CorsPolicyBuilder> policyBuilder )
        {
            Throw.CheckNotNullArgument( policyBuilder );
            var props = ((IHostApplicationBuilder)builder).Properties;
            if( !props.TryGetValue( typeof( CorsPolicyBuilder ), out var currentPolicy ) )
            {
                props.Add( typeof( CorsPolicyBuilder ), policyBuilder );
                builder.Services.AddCors();
                builder.AppendApplicationBuilder( DoUseCors( props ) );
            }
            else
            {
                props[typeof( CorsPolicyBuilder )] = policyBuilder;
            }
            return builder;

        }

        /// <summary>
        /// Add Cors support for a named policy. This method can be called multiple times: the last <paramref name="policyName"/>  wins.
        /// <para>
        /// Named policy must be defined by using <see cref="CorsServiceCollectionExtensions.AddCors(IServiceCollection, Action{CorsOptions})"/>
        /// and configuring the <see cref="CorsOptions"/>.
        /// </para>
        /// <para>
        /// This method, just like <see cref="AddCors(WebApplicationBuilder, Action{CorsPolicyBuilder})"/> and <see cref="AddUnsafeAllowAllCors(WebApplicationBuilder)"/>
        /// can be called multiple times: the last wins.
        /// </para>
        /// </summary>
        /// <param name="builder">This builder.</param>
        /// <param name="policyName">The policy name.</param>
        /// <returns>This builder.</returns>
        public static WebApplicationBuilder AddCors( this WebApplicationBuilder builder,
                                                     string policyName )
        {
            Throw.CheckNotNullOrWhiteSpaceArgument( policyName );
            var props = ((IHostApplicationBuilder)builder).Properties;
            if( !props.TryGetValue( typeof( CorsPolicyBuilder ), out var currentPolicy ) )
            {
                props.Add( typeof( CorsPolicyBuilder ), policyName );
                builder.Services.AddCors();
                builder.AppendApplicationBuilder( DoUseCors( props ) );
            }
            else
            {
                props[typeof( CorsPolicyBuilder )] = policyName;
            }
            return builder;
        }

        static Action<IApplicationBuilder> DoUseCors( IDictionary<object, object> props )
        {
            return app =>
            {
                var p = props[typeof( CorsPolicyBuilder )];
                if( p is string name ) app.UseCors( name );
                else app.UseCors( (Action<CorsPolicyBuilder>)p );
                props.Remove( typeof( CorsPolicyBuilder ) );
            };
        }
    }
}
