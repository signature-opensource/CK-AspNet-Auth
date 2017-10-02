using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CK.AspNet.Auth
{
    public static class CKAspNetAuthTicketReceivedContextExtensions
    {
        public static Task WebFrontAuthRemoteAuthenticateAsync<TPayload>( this TicketReceivedContext c, Action<TPayload> payloadConfigurator )
        {
            var authService = c.HttpContext.RequestServices.GetRequiredService<WebFrontAuthService>();
            return authService.HandleRemoteAuthentication( c, payloadConfigurator );
        }
    }
}
