using System;
using System.Collections.Generic;
using System.Text;

namespace CK.AspNet.Auth
{
    /// <summary>
    /// Defines the 3 different endpoints that can be used to start authentication.
    /// </summary>
    public enum WebFrontAuthLoginMode
    {
        /// <summary>
        /// Identifies the '.webfront/c/basicLogin' endpoint.
        /// This is available only if the <see cref="IWebFrontAuthLoginService.HasBasicLogin"/> is true.
        /// </summary>
        BasicLogin,

        /// <summary>
        /// Identifies the '.webfront/c/unsafeDirectLogin' endpoint.
        /// This endpoint is disabled by default and can only be enabled thanks to the
        /// optional <see cref="IWebFrontAuthUnsafeDirectLoginAllowService"/> service.
        /// </summary>
        UnsafeDirectLogin,

        /// <summary>
        /// Identifies the '.webfront/c/startLogin' endpoint used to challenge remote authentications.
        /// </summary>
        StartLogin
    }
}
