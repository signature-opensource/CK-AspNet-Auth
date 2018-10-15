using CK.Core;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace CK.AspNet.Auth
{
    /// <summary>
    /// Optional service that can allow calls to the dangerous '/c/unsafeDirectLogin'.
    /// Enabling calls to to this endpoint must be explicit: by default "403 - Forbidden"
    /// is always returned.
    /// </summary>
    /// <remarks>
    /// This reuses the interface marker from CK.Auth since we do not depend on CK.StObj.Model here.
    /// </remarks>
    public interface IWebFrontAuthUnsafeDirectLoginAllowService : CK.Auth.StObjSupport.ISingletonAmbientService
    {
        /// <summary>
        /// Predicate function that may allow calls to '/c/unsafeDirectLogin' for a
        /// scheme and a payload.
        /// </summary>
        /// <param name="ctx">The current context.</param>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="scheme">The authentication scheme.</param>
        /// <param name="payload">The login payload for the scheme.</param>
        /// <returns>True if the call must be allowed, false otherwise.</returns>
        Task<bool> AllowAsync( HttpContext ctx, IActivityMonitor monitor, string scheme, object payload );
    }
}
