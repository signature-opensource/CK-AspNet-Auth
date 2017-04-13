using CK.Auth;
using CK.DB.Auth;
using CK.SqlServer;
using CK.SqlServer.Setup;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CK.AspNet.AuthService
{
    public abstract class WebFrontAuthService
    {
        readonly IAuthenticationTypeSystem _typeSystem;
        AuthenticationInfoSecureDataFormat _tokenFormat;
        WebFrontAuthMiddlewareOptions _options;

        protected WebFrontAuthService(IAuthenticationTypeSystem typeSystem )
        {
            _typeSystem = typeSystem;
        }

        /// <summary>
        /// This is called by the WebFrontAuthMiddleware constructor.
        /// </summary>
        /// <param name="tokenFormat">The formatter for tokens.</param>
        /// <param name="options">The middleware options.</param>
        internal void Initialize(AuthenticationInfoSecureDataFormat tokenFormat, WebFrontAuthMiddlewareOptions options)
        {
            if (_tokenFormat != null) throw new InvalidOperationException("Only one WebFrontAuthMiddleware must be used.");
            Debug.Assert(tokenFormat != null);
            Debug.Assert(options != null);
            _tokenFormat = tokenFormat;
            _options = options;
        }

        internal IAuthenticationInfo EnsureAuthenticationInfo( HttpContext c )
        {
            IAuthenticationInfo authInfo = null;
            object o;
            if (c.Items.TryGetValue(typeof(IAuthenticationInfo), out o))
            {
                authInfo = (IAuthenticationInfo)o;
            }
            else
            {
                string authorization = c.Request.Headers[_options.BearerHeaderName];
                if (!string.IsNullOrEmpty(authorization)
                    && authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                {
                    Debug.Assert("Bearer ".Length == 7);
                    string token = authorization.Substring(7).Trim();
                    authInfo = _tokenFormat.Unprotect(token, GetTlsTokenBinding(c));
                }
                else authInfo = _typeSystem.AuthenticationInfo.None;
                c.Items.Add(typeof(IAuthenticationInfo), authInfo);
            }
            return authInfo;
        }

        internal string CreateToken(HttpContext c,IAuthenticationInfo authInfo)
        {
            return authInfo.IsNullOrNone() ? null : _tokenFormat.Protect(authInfo, GetTlsTokenBinding(c));
        }

        internal static string GetTlsTokenBinding( HttpContext c )
        {
            var binding = c.Features.Get<ITlsTokenBindingFeature>()?.GetProvidedTokenBindingId();
            return binding == null ? null : Convert.ToBase64String(binding);
        }

        /// <summary>
        /// Exposes the <see cref="IAuthenticationTypeSystem"/> used to handle authentication info 
        /// conversions.
        /// </summary>
        public IAuthenticationTypeSystem AuthenticationTypeSystem => _typeSystem;

        /// <summary>
        /// Gets whether <see cref="BasicLoginAsync(string, string)"/> is supported.
        /// </summary>
        public abstract bool HasBasicLogin { get; }

        /// <summary>
        /// Attempts to login. If it fails, null is returned. <see cref="HasBasicLogin"/> must be true for this
        /// to be called.
        /// </summary>
        /// <param name="userName">The user name.</param>
        /// <param name="password">The password.</param>
        /// <returns>The <see cref="IUserInfo"/> or null.</returns>
        public abstract Task<IUserInfo> BasicLoginAsync(string userName, string password);
    }

}
