using CK.AspNet.Auth;
using CK.Auth;
using Microsoft.AspNetCore.Authentication;
using System;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Offers support for WebFrontAuth on <see cref="AuthenticationBuilder"/>.
    /// </summary>
    public static class WebFrontAuthExtensions
    {
        /// <summary>
        /// Adds the WebFrontAuth authentication services without options configuration
        /// and default type system (<see cref="StdAuthenticationTypeSystem"/>)
        /// </summary>
        /// <param name="this">This Authentication builder.</param>
        /// <returns>Authentication builder to enable fluent syntax.</returns>
        public static AuthenticationBuilder AddWebFrontAuth( this AuthenticationBuilder @this )
        {
            return @this.AddWebFrontAuth<StdAuthenticationTypeSystem>( null );
        }

        /// <summary>
        /// Adds the WebFrontAuth authentication services with options configuration
        /// and default type system (<see cref="StdAuthenticationTypeSystem"/>)
        /// </summary>
        /// <param name="this">This Authentication builder.</param>
        /// <param name="configure">Configuration action.</param>
        /// <returns>Authentication builder to enable fluent syntax.</returns>
        public static AuthenticationBuilder AddWebFrontAuth( this AuthenticationBuilder @this, Action<WebFrontAuthOptions> configure )
        {
            return @this.AddWebFrontAuth<StdAuthenticationTypeSystem>( configure );
        }

        /// <summary>
        /// Adds the WebFrontAuth authentication services with options configuration
        /// and explicit <see cref="IAuthenticationTypeSystem"/> implementation.
        /// </summary>
        /// <typeparam name="TTypeSystem">Implementation type of type system abstraction.</typeparam>
        /// <param name="this">This Authentication builder.</param>
        /// <param name="configure">Configuration action.</param>
        /// <returns>Authentication builder to enable fluent syntax.</returns>
        public static AuthenticationBuilder AddWebFrontAuth<TTypeSystem>( this AuthenticationBuilder @this, Action<WebFrontAuthOptions> configure )
            where TTypeSystem : class, IAuthenticationTypeSystem
        {
            @this.Services.AddSingleton<IAuthenticationTypeSystem, TTypeSystem>();
            @this.Services.AddSingleton<WebFrontAuthService>();
            @this.AddScheme<WebFrontAuthOptions, WebFrontAuthHandler>( WebFrontAuthOptions.OnlyAuthenticationScheme, "Web Front Authentication", configure );
            return @this;
        }
    }
}
