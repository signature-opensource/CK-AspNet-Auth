using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using CK.Auth;
using CK.Core;

namespace CK.AspNet.Auth;

/// <summary>
/// Optional service that, when registered, enables automatic account binding.
/// Implementation may consider that when current authentication is <see cref="AuthLevel.Critical"/> it is safe
/// to bind the account.
/// </summary>
[SingletonContainerConfiguredService]
public interface IWebFrontAuthAutoBindingAccountService : IAutoService
{
    /// <summary>
    /// Called for each failed login when the user is currently logged in.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="context">Account binding context.</param>
    /// <returns>
    /// The login result where the <see cref="UserLoginResult.UserInfo"/> may have its <see cref="IUserInfo.Schemes"/>
    /// updated with the new one (the current logged in user available on <see cref="IWebFrontAuthAutoBindingAccountContext.InitialAuthentication"/>
    /// may be returned but this is quite useless).
    /// <para>
    /// Null to return the standard User.NoAutoBinding/"Automatic account binding is disabled." error
    /// or the error identifier and error text have been set via <see cref="IWebFrontAuthAutoBindingAccountContext.SetError(string, string)"/>
    /// or <see cref="IWebFrontAuthAutoBindingAccountContext.SetError(Exception)"/>.
    /// </para>
    /// </returns>
    Task<UserLoginResult?> BindAccountAsync( IActivityMonitor monitor, IWebFrontAuthAutoBindingAccountContext context );
}
