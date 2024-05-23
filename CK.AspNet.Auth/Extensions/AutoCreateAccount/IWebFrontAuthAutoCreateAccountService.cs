using CK.Auth;
using CK.Core;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace CK.AspNet.Auth
{
    /// <summary>
    /// Optional service that, when registered, enables automatic account creation.
    /// This should be used with care.
    /// The <see cref="IWebFrontAuthAutoCreateAccountContext.UserData"/> should typically
    /// contain a special key (like an "InvitationToken") with a relatively short life timed and verifiable value that should be
    /// required to actually create the account and log in the user.
    /// Also, not all schemes should be systematically supported, nor all <see cref="IWebFrontAuthAutoCreateAccountContext.LoginMode"/>.
    /// </summary>
    [ContainerConfiguredSingletonService]
    public interface IWebFrontAuthAutoCreateAccountService : ISingletonAutoService
    {
        /// <summary>
        /// Called for each failed login when <see cref="UserLoginResult.IsUnregisteredUser"/> is true and when there is
        /// no current authentication.
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="context">Account creation context.</param>
        /// <returns>
        /// The login result that may be automatically created AND logged in.
        /// Null to return the standard User.NoAutoRegistration/"Automatic user registration is disabled." error
        /// or the error identifier and error text have been set via <see cref="IWebFrontAuthAutoCreateAccountContext.SetError(string, string)"/>
        /// or <see cref="IWebFrontAuthAutoCreateAccountContext.SetError(Exception)"/>.
        /// </returns>
        Task<UserLoginResult?> CreateAccountAndLoginAsync( IActivityMonitor monitor, IWebFrontAuthAutoCreateAccountContext context );
    }
}
