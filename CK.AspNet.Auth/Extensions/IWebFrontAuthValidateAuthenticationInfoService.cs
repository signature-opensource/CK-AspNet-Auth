using CK.Auth;
using CK.Core;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace CK.AspNet.Auth
{
    /// <summary>
    /// Optional service that will be called each time a token is successfully read
    /// and a <see cref="IAuthenticationInfo"/> is about to be associated to the current
    /// request.
    /// <para>
    /// Note that this is not called during the login itself, but only when the authentication info
    /// is restored from the request (from the bearer or the cookies).
    /// </para>
    /// </summary>
    public interface IWebFrontAuthValidateAuthenticationInfoService : ISingletonAutoService
    {
        /// <summary>
        /// Validates or changes the current authentication (returning null sets the <see cref="IAuthenticationInfo.Level"/> to <see cref="AuthLevel.None"/>).
        /// Note that the returned information is valid only for this request (this doesn't update the cookies).
        /// <para>
        /// Any exception raised by this method is not intercepted and will cancel the request.
        /// </para>
        /// </summary>
        /// <param name="ctx">The current context.</param>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="authInfo">The current authentication information.</param>
        /// <returns>The unchanged <paramref name="authInfo"/> or a new one, or null to revoke it.</returns>
        public ValueTask<IAuthenticationInfo?> ValidateAuthenticationInfoAsync( HttpContext ctx, IActivityMonitor monitor, IAuthenticationInfo authInfo );
    }
}
