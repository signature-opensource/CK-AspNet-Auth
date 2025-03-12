using CK.Auth;
using CK.Core;
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;

namespace CK.AspNet.Auth;

/// <summary>
/// Optional service that controls user impersonation either by user identifier or user name.
/// Impersonation is not an actual login, it must have no visible impact on the impersonated user data.
/// </summary>
[SingletonContainerConfiguredService]
public interface IWebFrontAuthImpersonationService : IAutoService
{
    /// <summary>
    /// Attempts to impersonate the current user into another one.
    /// Should return the user information on success and null if impersonation is not allowed.
    /// </summary>
    /// <param name="ctx">The HttpContext.</param>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="info">The current user information.</param>
    /// <param name="userId">The target user identifier.</param>
    /// <returns>The target impersonated user or null if impersonation is not possible.</returns>
    Task<IUserInfo?> ImpersonateAsync( HttpContext ctx,
                                       IActivityMonitor monitor,
                                       IAuthenticationInfo info,
                                       int userId );

    /// <summary>
    /// Attempts to impersonate the current user into another one.
    /// Should return the user information on success and null if impersonation is not allowed.
    /// </summary>
    /// <param name="ctx">The HttpContext.</param>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="info">The current user information.</param>
    /// <param name="userName">The target user name.</param>
    /// <returns>The target impersonated user or null if impersonation is not possible.</returns>
    Task<IUserInfo?> ImpersonateAsync( HttpContext ctx,
                                       IActivityMonitor monitor,
                                       IAuthenticationInfo info,
                                       string userName );
}
