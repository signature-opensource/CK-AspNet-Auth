using CK.Core;
using Microsoft.AspNetCore.Authentication;
using System.Threading.Tasks;

namespace CK.AspNet.Auth;

/// <summary>
/// Optional service that can handle dynamic scopes.
/// This service provides the scopes that must be submitted to an authentication provider.
/// <para>
/// Updating the actual scopes that have been accepted or rejected is a specific process
/// that must be implemented for each provider.
/// </para>
/// <para>
/// For instance: Facebook requires to use its GraphQL API to know which scopes have been
/// accepted or rejected by the user.
/// Others simply returns these informations in the <see cref="TicketReceivedContext"/>.
/// </para>
/// </summary>
[SingletonContainerConfiguredService]
public interface IWebFrontAuthDynamicScopeProvider : IAutoService
{
    /// <summary>
    /// Called at the start of the external login flow.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="context">The context.</param>
    /// <returns>Scopes that should be submitted.</returns>
    Task<string[]> GetScopesAsync( IActivityMonitor monitor, WebFrontAuthStartLoginContext context );
}
