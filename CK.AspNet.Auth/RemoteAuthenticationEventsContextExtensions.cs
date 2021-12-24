using CK.Auth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CK.AspNet.Auth
{
    /// <summary>
    /// Helper on <see cref="TicketReceivedContext"/> and <see cref="RemoteFailureContext"/>.
    /// </summary>
    public static class RemoteAuthenticationEventsContextExtensions
    {
        /// <summary>
        /// Obsolete.
        /// </summary>
        /// <typeparam name="TPayload">Type of the payload.</typeparam>
        /// <param name="c">This ticket received context.</param>
        /// <param name="payloadConfigurator">Action that must configure the payload.</param>
        /// <returns>The awaitable.</returns>
        [Obsolete( "Use WebFrontAuthOnTicketReceivedAsync (renaming).", error: false )]
        public static Task WebFrontAuthRemoteAuthenticateAsync<TPayload>( this TicketReceivedContext c, Action<TPayload> payloadConfigurator )
            => WebFrontAuthOnTicketReceivedAsync( c, payloadConfigurator );

        /// <summary>
        /// Simple API used from <see cref="RemoteAuthenticationEvents.OnTicketReceived"/> to handle
        /// external authentication: <see cref="WebFrontAuthService.HandleRemoteAuthenticationAsync{T}(TicketReceivedContext, Action{T})"/>
        /// is called.
        /// </summary>
        /// <typeparam name="TPayload">Type of the payload.</typeparam>
        /// <param name="c">This ticket received context.</param>
        /// <param name="payloadConfigurator">Action that must configure the payload.</param>
        /// <returns>The awaitable.</returns>
        public static Task WebFrontAuthOnTicketReceivedAsync<TPayload>( this TicketReceivedContext c, Action<TPayload> payloadConfigurator )
        {
            var authService = c.HttpContext.RequestServices.GetRequiredService<WebFrontAuthService>();
            return authService.HandleRemoteAuthenticationAsync( c, payloadConfigurator );
        }

        /// <summary>
        /// Simple API used from <see cref="RemoteAuthenticationEvents.OnRemoteFailure"/> to handle remote failure authentication:
        /// the <paramref name="errorId"/> and <paramref name="errorText"/> are returned to the client.
        /// (This method calls <see cref="HandleRequestContext{T}.HandleResponse()"/> that ends any further response processing.)
        /// </summary>
        /// <param name="f">This remote failure context.</param>
        /// <param name="setUnsafeLevel">
        /// True to downgrade the current authentication to <see cref="AuthLevel.Unsafe"/>.
        /// By default the current authentication is kept as-is.
        /// </param>
        /// <param name="errorId">
        /// Error identifier: should be a dotted identifier that could easily be used as a resource
        /// name (to map to translations in different languages).
        /// </param>
        /// <param name="errorText">When null, <see cref="RemoteFailureContext.Failure"/>'s <see cref="Exception.Message"/> is used.</param>
        /// <returns>The awaitable.</returns>
        public static Task WebFrontAuthOnRemoteFailureAsync( this RemoteFailureContext f, bool setUnsafeLevel = false, string errorId = "RemoteFailure", string? errorText = null )
        {
            return OnErrorAsync( f, f.Properties, setUnsafeLevel, errorId, errorText ?? f.Failure.Message );
        }

        /// <summary>
        /// Simple API used from <see cref="RemoteAuthenticationEvents.OnAccessDenied"/> to handle remote access denied:
        /// the <paramref name="errorId"/> and <paramref name="errorText"/> are returned to the client.
        /// (This method calls <see cref="HandleRequestContext{T}.HandleResponse()"/> that ends any further response processing.)
        /// </summary>
        /// <param name="d">This remote failure context.</param>
        /// <param name="setUnsafeLevel">
        /// True to downgrade the current authentication to <see cref="AuthLevel.Unsafe"/>.
        /// By default the current authentication is kept as-is.
        /// </param>
        /// <param name="errorId">
        /// Error identifier: should be a dotted identifier that could easily be used as a resource
        /// name (to map to translations in different languages).
        /// </param>
        /// <param name="errorText">When null, <paramref name="errorId"/> is used.</param>
        /// <returns>The awaitable.</returns>
        public static Task WebFrontAuthOnAccessDeniedAsync( this AccessDeniedContext d,
                                                            bool setUnsafeLevel = false,
                                                            string errorId = "AccessDenied",
                                                            string? errorText = null )
        {
            return OnErrorAsync( d, d.Properties, setUnsafeLevel, errorId, errorText ?? errorId );
        }

        static Task OnErrorAsync( HandleRequestContext<RemoteAuthenticationOptions> h,
                                  AuthenticationProperties properties,
                                  bool setUnsafeLevel,
                                  string errorId,
                                  string errorText )
        {
            h.HandleResponse();
            var authService = h.HttpContext.RequestServices.GetRequiredService<WebFrontAuthService>();
            authService.GetWFAData( h.HttpContext, properties, out var fAuth, out var initialScheme, out var callerOrigin, out var returnUrl, out var userData );
            if( setUnsafeLevel )
            {
                fAuth = fAuth.SetUnsafeLevel();
            }
            return authService.SendRemoteAuthenticationErrorAsync( h.HttpContext, fAuth, returnUrl, callerOrigin, errorId, errorText, initialScheme, h.Scheme.Name, userData );
        }

        /// <summary>
        /// Extracts the initial authentication from this context (from the "WFA-C" key of <see cref="RemoteFailureContext.Properties"/>).
        /// </summary>
        /// <param name="this">This ticket received context.</param>
        /// <returns>The initial authentication.</returns>
        public static IAuthenticationInfo GetTicketAuthenticationInfo( this TicketReceivedContext @this ) => GetFrontAuthenticationInfo( @this.HttpContext, @this.Properties ).Info;

        /// <summary>
        /// Extracts the initial authentication from this context (from the "WFA-C" key of <see cref="RemoteFailureContext.Properties"/>).
        /// </summary>
        /// <param name="this">This failure context.</param>
        /// <returns>The initial authentication.</returns>
        public static IAuthenticationInfo GetTicketAuthenticationInfo( this RemoteFailureContext @this ) => GetFrontAuthenticationInfo( @this.HttpContext, @this.Properties ).Info;

        /// <summary>
        /// Extracts the initial authentication from this context (from the "WFA-C" key of <see cref="RemoteFailureContext.Properties"/>).
        /// </summary>
        /// <param name="this">This failure context.</param>
        /// <returns>The initial authentication.</returns>
        public static IAuthenticationInfo GetTicketAuthenticationInfo( this AccessDeniedContext d ) => GetFrontAuthenticationInfo( d.HttpContext, d.Properties ).Info;

        static FrontAuthenticationInfo GetFrontAuthenticationInfo( HttpContext httpContext, AuthenticationProperties properties )
        {
            return httpContext.RequestServices.GetRequiredService<WebFrontAuthService>().GetFrontAuthenticationInfo( httpContext, properties );
        }
    }
}
