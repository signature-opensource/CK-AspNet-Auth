using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using CK.Core;

namespace CK.AspNet.Auth
{
    /// <summary>
    /// Optional service that, when registered, enables automatic account binding.
    /// This should be used with care.
    /// The <see cref="IWebFrontAuthAutoBindingAccountContext.UserData"/> should typically
    /// contain a special key (like an "BindingToken") with a relatively short life timed and verifiable value that should be
    /// required to actually bind the provider to the account.
    /// Also, not all schemes should be systematically supported, nor all <see cref="IWebFrontAuthAutoBindingAccountContext.LoginMode"/>.
    /// </summary>
    /// <remarks>
    /// This reuses the interface marker from CK.Auth since we do not depend on CK.StObj.Model here.
    /// </remarks>
    public interface IWebFrontAuthAutoBindingAccountService : CK.Auth.StObjSupport.ISingletonAutoService
    {
        /// <summary>
        /// Called for each failed login when <see cref="UserLoginResult.IsUnregisteredUser"/> is true and when the user
        /// is already authenticated.
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="context">Account binding context.</param>
        /// <returns>
        /// The login result that may be automatically binded AND logged in.
        /// Null to return the standard User.NoAutoBinding/"Automatic account binding is disabled." error
        /// or the error identifier and error text have been set via <see cref="IWebFrontAuthAutoBindingAccountContext.SetError(string, string)"/>
        /// or <see cref="IWebFrontAuthAutoBindingAccountContext.SetError(Exception)"/>.
        /// </returns>
        Task<AccountBindingResult> BindAccountAsync( IActivityMonitor monitor, IWebFrontAuthAutoBindingAccountContext context );
    }
}
