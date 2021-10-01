using CK.Auth;
using CK.Core;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace CK.AspNet.Auth
{
    /// <summary>
    /// Optional service that can handle dynamic scopes.
    /// This service provides the scopes that must be submitted to an authentication provider.
    /// Updating the actual scopes that have been accepted or rejected is a specific process
    /// that must be implemented for each provider.
    /// <para>
    /// For instance: Facebook requires to use its GraphQL API to know which scopes have been
    /// accepted or rejected by the user.
    /// Others simply returns these informations in the <see cref="TicketReceivedContext"/>.
    /// </para>
    /// </summary>
    public interface IWebFrontAuthDynamicScopeProvider : ISingletonAutoService
    {
        /// <summary>
        /// Called at the start of the external login flow.
        /// </summary>
        /// <param name="m">The monitor to use.</param>
        /// <param name="context">The context.</param>
        /// <returns>Scopes that should be submitted.</returns>
        Task<string[]> GetScopesAsync( IActivityMonitor m, WebFrontAuthStartLoginContext context );
    }
}
