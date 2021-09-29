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
        /// Simple API used from <see cref="RemoteAuthenticationEvents.OnTicketReceived"/> to handle
        /// external authentication: <see cref="WebFrontAuthService.HandleRemoteAuthentication{T}(TicketReceivedContext, Action{T})"/>
        /// is called.
        /// </summary>
        /// <typeparam name="TPayload">Type of the payload.</typeparam>
        /// <param name="c">This ticket received context.</param>
        /// <param name="payloadConfigurator">Action that must configure the payload.</param>
        /// <returns>The awaitable.</returns>
        public static Task WebFrontAuthRemoteAuthenticateAsync<TPayload>( this TicketReceivedContext c, Action<TPayload> payloadConfigurator )
        {
            var authService = c.HttpContext.RequestServices.GetRequiredService<WebFrontAuthService>();
            return authService.HandleRemoteAuthentication( c, payloadConfigurator );
        }

        /// <summary>
        /// Simple API used from <see cref="RemoteAuthenticationEvents.OnRemoteFailure"/> to handle remote failure authentication:
        /// the <paramref name="errorId"/> and <paramref name="errorText"/> are returned to the client.
        /// (This method calls <see cref="HandleRequestContext{T}.HandleResponse()"/> that ends any further response processing.)
        /// </summary>
        /// <param name="f">This remote failure context.</param>
        /// <param name="errorId">
        /// Error identifier: should be a dotted identifier that could easily be used as a resource
        /// name (to map to translations in different languages).
        /// </param>
        /// <param name="errorText">When null, <see cref="RemoteFailureContext.Failure"/>'s <see cref="Exception.Message"/> is used.</param>
        /// <returns>The awaitable.</returns>
        public static Task WebFrontAuthRemoteFailureAsync( this RemoteFailureContext f, string errorId = "RemoteFailure", string? errorText = null )
        {
            return OnError( f, f.Properties, errorId, errorText ?? f.Failure.Message );
        }

        /// <summary>
        /// Simple API used from <see cref="RemoteAuthenticationEvents.OnAccessDenied"/> to handle remote access denied:
        /// the <paramref name="errorId"/> and <paramref name="errorText"/> are returned to the client.
        /// (This method calls <see cref="HandleRequestContext{T}.HandleResponse()"/> that ends any further response processing.)
        /// </summary>
        /// <param name="d">This remote failure context.</param>
        /// <param name="errorId">
        /// Error identifier: should be a dotted identifier that could easily be used as a resource
        /// name (to map to translations in different languages).
        /// </param>
        /// <param name="errorText">When null, <paramref name="errorId"/> is used.</param>
        /// <returns>The awaitable.</returns>
        public static Task WebFrontAuthRemoteFailureAsync( this AccessDeniedContext d, string errorId = "AccessDenied", string? errorText = null )
        {
            return OnError( d, d.Properties, errorId, errorText ?? errorId );
        }

        static Task OnError( HandleRequestContext<RemoteAuthenticationOptions> h, AuthenticationProperties properties, string errorId, string errorText )
        {
            h.HandleResponse();
            var authService = h.HttpContext.RequestServices.GetRequiredService<WebFrontAuthService>();
            WebFrontAuthHandler.ExtractClearWFAData( properties, out _, out var deviceId, out var initialScheme, out var returnUrl, out var callerOrigin );
            return authService.SendRemoteAuthenticationError( h.HttpContext, deviceId, returnUrl, callerOrigin, errorId, errorText, initialScheme );
        }

        /// <summary>
        /// Extracts the initial authentication from this context (from the "WFA-C" key of <see cref="RemoteFailureContext.Properties"/>).
        /// </summary>
        /// <param name="this">This failure context.</param>
        /// <returns>The initial authentication.</returns>
        public static IAuthenticationInfo GetTicketAuthenticationInfo( this RemoteFailureContext @this ) => GetAuthenticationInfo( @this.HttpContext, @this.Properties );

        /// <summary>
        /// Extracts the initial authentication from this context (from the "WFA-C" key of <see cref="RemoteFailureContext.Properties"/>).
        /// </summary>
        /// <param name="this">This failure context.</param>
        /// <returns>The initial authentication.</returns>
        public static IAuthenticationInfo GetTicketAuthenticationInfo( this AccessDeniedContext d ) => GetAuthenticationInfo( d.HttpContext, d.Properties );

        static IAuthenticationInfo GetAuthenticationInfo( HttpContext h, AuthenticationProperties properties )
        {
            if( properties.Items.TryGetValue( "WFA-C", out var currentAuth ) )
            {
                var authService = h.RequestServices.GetRequiredService<WebFrontAuthService>();
                return authService.UnprotectAuthenticationInfo( h, currentAuth ).Info;
            }
            WebFrontAuthHandler.ExtractClearWFAData( properties, out _, out var deviceId, out var _, out var _, out var _ );
            var typeSystem = h.RequestServices.GetRequiredService<IAuthenticationTypeSystem>();
            return typeSystem.AuthenticationInfo.Create( null, deviceId: deviceId );
        }

    }
}
