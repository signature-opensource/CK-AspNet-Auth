using Microsoft.AspNetCore.Authentication;
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
            f.HandleResponse();
            if( errorText == null ) errorText = f.Failure.Message;
            var authService = f.HttpContext.RequestServices.GetRequiredService<WebFrontAuthService>();
            WebFrontAuthHandler.ExtractClearWFAData( f.Properties, out _, out var deviceId, out var initialScheme, out var returnUrl, out var callerOrigin );
            return authService.SendRemoteAuthenticationError( f.HttpContext, deviceId, returnUrl, callerOrigin, errorId, errorText, initialScheme );
        }

    }
}
