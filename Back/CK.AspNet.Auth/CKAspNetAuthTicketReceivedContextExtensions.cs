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
    /// Helper on <see cref="TicketReceivedContext"/>.
    /// </summary>
    public static class CKAspNetAuthTicketReceivedContextExtensions
    {
        /// <summary>
        /// Simple API typically used from <see cref="RemoteAuthenticationEvents.OnTicketReceived"/>
        /// to handle external authentication: <see cref="WebFrontAuthService.HandleRemoteAuthentication{T}(TicketReceivedContext, Action{T})"/>
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
    }
}
