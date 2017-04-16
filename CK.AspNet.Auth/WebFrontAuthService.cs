using CK.Auth;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading.Tasks;

namespace CK.AspNet.Auth
{
    /// <summary>
    /// Base class for an actual, final, authentication service as well as a decorator of an existing service.
    /// </summary>
    public abstract class WebFrontAuthService
    {
        readonly WebFrontAuthService _inner;
        readonly IAuthenticationTypeSystem _typeSystem;
        AuthenticationInfoSecureDataFormat _tokenFormat;
        WebFrontAuthMiddlewareOptions _options;

        /// <summary>
        /// Initializes a new <see cref="WebFrontAuthService"/>.
        /// </summary>
        /// <param name="typeSystem">A <see cref="IAuthenticationTypeSystem"/>.</param>
        protected WebFrontAuthService(IAuthenticationTypeSystem typeSystem, WebFrontAuthService inner = null)
        {
            if (typeSystem == null) throw new ArgumentNullException(nameof(typeSystem));
            _typeSystem = typeSystem;
            _inner = inner;
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
            if (_inner != null) _inner.Initialize(tokenFormat, options);
        }

        /// <summary>
        /// Handles cached authentication header or calls <see cref="ReadAndCacheAuthenticationHeader"/>.
        /// </summary>
        /// <param name="c">The context.</param>
        /// <returns>
        /// The cached or resolved authentication info. 
        /// Never null, can be <see cref="IAuthenticationInfoType.None"/>.
        /// </returns>
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
                authInfo = ReadAndCacheAuthenticationHeader(c);
            }
            return authInfo;
        }

        /// <summary>
        /// Reads authentication header and caches authentication in request items.
        /// </summary>
        /// <param name="c">The context.</param>
        /// <returns>
        /// The cached or resolved authentication info. 
        /// Never null, can be <see cref="IAuthenticationInfoType.None"/>.
        /// </returns>
        internal IAuthenticationInfo ReadAndCacheAuthenticationHeader(HttpContext c)
        {
            Debug.Assert(!c.Items.ContainsKey(typeof(IAuthenticationInfo)));
            IAuthenticationInfo authInfo;
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
            return authInfo;
        }

        /// <summary>
        /// Returns the token (null if authInfo is null or none).
        /// </summary>
        /// <param name="c">The context.</param>
        /// <param name="authInfo">The authentication info. Can be null.</param>
        /// <returns>The token (can be null).</returns>
        internal string CreateToken(HttpContext c, IAuthenticationInfo authInfo)
        {
            return authInfo.IsNullOrNone() ? null : _tokenFormat.Protect(authInfo, GetTlsTokenBinding(c));
        }

        internal static string GetTlsTokenBinding( HttpContext c )
        {
            var binding = c.Features.Get<ITlsTokenBindingFeature>()?.GetProvidedTokenBindingId();
            return binding == null ? null : Convert.ToBase64String(binding);
        }

        /// <summary>
        /// Gets the middleware options.
        /// </summary>
        protected WebFrontAuthMiddlewareOptions Options => _options;

        /// <summary>
        /// Gets the inner service or null if this is no a decorator.
        /// </summary>
        protected WebFrontAuthService InnerService => _inner;

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
        /// to be called otherwise an <see cref="InvalidOperationException"/> is thrown.
        /// </summary>
        /// <param name="userName">The user name.</param>
        /// <param name="password">The password.</param>
        /// <returns>The <see cref="IUserInfo"/> or null.</returns>
        public abstract Task<IUserInfo> BasicLoginAsync(string userName, string password);

        /// <summary>
        /// Gets the existing providers's name.
        /// </summary>
        public abstract IReadOnlyList<string> Providers { get; }

        /// <summary>
        /// Attempts to login a user using an existing provider.
        /// The provider must exist and the payload must be compatible otherwise an <see cref="ArgumentException"/>
        /// is thrown.
        /// </summary>
        /// <param name="providerName">The provider name to use.</param>
        /// <param name="payload">The provider dependent login payload.</param>
        /// <returns>The <see cref="IUserInfo"/> or null.</returns>
        public abstract Task<IUserInfo> LoginAsync(string providerName, object payload);
    }

}
