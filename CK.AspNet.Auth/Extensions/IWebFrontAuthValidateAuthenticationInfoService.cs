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
    /// </summary>
    public interface IWebFrontAuthValidateAuthenticationInfoService : CK.Auth.StObjSupport.ISingletonAutoService
    {
        /// <summary>
        /// Validates or changes the current authentication (returning null revokes it).
        /// Note that the returned information is valid only for this request (this doesn't update the
        /// cookies).
        /// <para>
        /// Any exception raised by this method is not intercepted and will cancel the request.
        /// </para>
        /// </summary>
        /// <param name="ctx">The current context.</param>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="authInfo">The current authentication information.</param>
        /// <returns>The unchanged <paramref name="authInfo"/> or a new one or null to revoke it.</returns>
        public ValueTask<IAuthenticationInfo?> ValidateAuthenticationInfoAsync( HttpContext ctx, IActivityMonitor monitor, IAuthenticationInfo authInfo );
    }
}
