using CK.Auth;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.AspNetCore.Http.Features.Authentication;
using Microsoft.Extensions.Primitives;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;

namespace CK.AspNet.Auth
{
    /// <summary>
    /// Encapsulates the sign in data issued by an external provider.
    /// </summary>
    public class WebFrontAuthSignInContext
    {
        readonly WebFrontAuthService _authService;

        internal WebFrontAuthSignInContext( 
            HttpContext ctx, 
            WebFrontAuthService authService, 
            string callingScheme,
            AuthenticationProperties authProps,
            ClaimsPrincipal principal,
            string provider, 
            IAuthenticationInfo auth, 
            List<KeyValuePair<string, StringValues>> userData )
        {
            HttpContext = ctx;
            _authService = authService;
            CallingScheme = callingScheme;
            AuthenticationProperties = authProps;
            InitialProvider = provider;
            InitialAuthentication = auth;
            UserData = userData;
        }

        /// <summary>
        /// Internally used by WebFrontAuthService to handle the final response.
        /// </summary>
        internal readonly HttpContext HttpContext;

        /// <summary>
        /// Gets the Authentication properties.
        /// </summary>
        public AuthenticationProperties AuthenticationProperties { get; }

        /// <summary>
        /// Gets the ClaimsPrincipal.
        /// </summary>
        public ClaimsPrincipal Principal { get; }

        /// <summary>
        /// Gets the authentication provider on which .webfront/c/starLogin has been called.
        /// </summary>
        public string InitialProvider { get; }

        /// <summary>
        /// Gets the calling authentication scheme.
        /// </summary>
        public string CallingScheme { get; }

        /// <summary>
        /// Gets the current authentication when .webfront/c/starLogin has been called.
        /// </summary>
        public IAuthenticationInfo InitialAuthentication { get; }

        /// <summary>
        /// Gets the query (fer GET) or form (when POST was used) data of the 
        /// initial .webfront/c/starLogin call as a mutable list.
        /// </summary>
        public List<KeyValuePair<string, StringValues>> UserData { get; }

    }

}
