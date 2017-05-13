using CK.Auth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
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
        const string AuthCookieName = ".webFront";
        const string UnsafeCookieName = ".webFrontLT";

        readonly WebFrontAuthService _inner;
        readonly IAuthenticationTypeSystem _typeSystem;

        AuthenticationInfoSecureDataFormat _tokenFormat;
        AuthenticationInfoSecureDataFormat _cookieFormat;
        WebFrontAuthMiddlewareOptions _options;
        string _cookiePath;
        TimeSpan _halfSlidingExpirationTime;

        /// <summary>
        /// Initializes a new <see cref="WebFrontAuthService"/>.
        /// </summary>
        /// <param name="typeSystem">A <see cref="IAuthenticationTypeSystem"/>.</param>
        /// <param name="inner">Optional decorated service.</param>
        protected WebFrontAuthService(IAuthenticationTypeSystem typeSystem, WebFrontAuthService inner = null)
        {
            if (typeSystem == null) throw new ArgumentNullException(nameof(typeSystem));
            _typeSystem = typeSystem;
            _inner = inner;
        }

        /// <summary>
        /// This is called by the WebFrontAuthMiddleware constructor.
        /// </summary>
        /// <param name="cookieFormat">The formatter for cookies.</param>
        /// <param name="tokenFormat">The formatter for tokens.</param>
        /// <param name="options">The middleware options.</param>
        internal void Initialize(AuthenticationInfoSecureDataFormat cookieFormat, AuthenticationInfoSecureDataFormat tokenFormat, WebFrontAuthMiddlewareOptions options)
        {
            if (_tokenFormat != null) throw new InvalidOperationException("Only one WebFrontAuthMiddleware must be used.");
            Debug.Assert(tokenFormat != null);
            Debug.Assert(options != null);
            _cookieFormat = cookieFormat;
            _tokenFormat = tokenFormat;
            _options = options;
            _cookiePath = options.EntryPath + "/c/";
            _halfSlidingExpirationTime = new TimeSpan(options.SlidingExpirationTime.Ticks / 2);
            if (_inner != null) _inner.Initialize(cookieFormat, tokenFormat, options);
        }

        /// <summary>
        /// Handles cached authentication header or calls <see cref="ReadAndCacheAuthenticationHeader"/>.
        /// Never null, can be <see cref="IAuthenticationInfoType.None"/>.
        /// </summary>
        /// <param name="c">The context.</param>
        /// <returns>
        /// The cached or resolved authentication info. 
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
        /// Reads authentication header if possible or uses authentication Cookie (and ultimately falls back to 
        /// long terme cookie) and caches authentication in request items.
        /// </summary>
        /// <param name="c">The context.</param>
        /// <returns>
        /// The cached or resolved authentication info. 
        /// Never null, can be <see cref="IAuthenticationInfoType.None"/>.
        /// </returns>
        internal IAuthenticationInfo ReadAndCacheAuthenticationHeader(HttpContext c)
        {
            Debug.Assert(!c.Items.ContainsKey(typeof(IAuthenticationInfo)));
            IAuthenticationInfo authInfo = null;
            try
            {
                // First try from the bearer: this is always the preferred way.
                string authorization = c.Request.Headers[_options.BearerHeaderName];
                if (!string.IsNullOrEmpty(authorization)
                    && authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                {
                    Debug.Assert("Bearer ".Length == 7);
                    string token = authorization.Substring(7).Trim();
                    authInfo = _tokenFormat.Unprotect(token, GetTlsTokenBinding(c));
                }
                else
                {
                    // Best case is when we have the authentication cookie, otherwise use the long term cookie.
                    string cookie;
                    if (Options.CookieMode != AuthenticationCookieMode.None && c.Request.Cookies.TryGetValue(AuthCookieName, out cookie))
                    {
                        authInfo = _cookieFormat.Unprotect(cookie, GetTlsTokenBinding(c));
                    }
                    else if (Options.UseLongTermCookie && c.Request.Cookies.TryGetValue(UnsafeCookieName, out cookie))
                    {
                        IUserInfo info = _typeSystem.UserInfo.FromJObject(JObject.Parse(cookie));
                        authInfo = _typeSystem.AuthenticationInfo.Create(info);
                    }
                }
                if (authInfo == null) authInfo = _typeSystem.AuthenticationInfo.None;
                // Upon each authentication, when rooted Cookies are used and the SlidingExpiration is on, handles it.
                if (authInfo.Level >= AuthLevel.Normal
                    && Options.CookieMode == AuthenticationCookieMode.RootPath
                    && _halfSlidingExpirationTime > TimeSpan.Zero
                    && authInfo.Expires.Value <= DateTime.UtcNow + _halfSlidingExpirationTime)
                {
                    var authInfo2 = authInfo.SetExpires(DateTime.UtcNow + Options.SlidingExpirationTime);
                    SetCookies(c, authInfo = authInfo2);
                }
            }
            catch( Exception ex )
            {
                _options.OnError(c,ex);
                authInfo = _typeSystem.AuthenticationInfo.None;
            }
            c.Items.Add(typeof(IAuthenticationInfo), authInfo);
            return authInfo;
        }

        #region Cookie management

        internal void Logout( HttpContext ctx )
        {
            ClearCookie(ctx, AuthCookieName);
            if (ctx.Request.Query.ContainsKey("full")) ClearCookie(ctx, UnsafeCookieName);
        }

        internal void SetCookies(HttpContext ctx, IAuthenticationInfo authInfo)
        {
            if (authInfo != null && Options.UseLongTermCookie && authInfo.UnsafeActualUser.UserId != 0)
            {
                string value = _typeSystem.UserInfo.ToJObject(authInfo.UnsafeActualUser).ToString(Formatting.None);
                ctx.Response.Cookies.Append(UnsafeCookieName, value, CreateUnsafeCookieOptions(DateTime.UtcNow + Options.UnsafeExpireTimeSpan));
            }
            else ClearCookie(ctx, UnsafeCookieName);
            if (authInfo != null && Options.CookieMode != AuthenticationCookieMode.None && authInfo.Level >= AuthLevel.Normal)
            {
                Debug.Assert(authInfo.Expires.HasValue);
                string value = _cookieFormat.Protect(authInfo, WebFrontAuthService.GetTlsTokenBinding(ctx));
                ctx.Response.Cookies.Append(AuthCookieName, value, CreateAuthCookieOptions(ctx, authInfo.Expires));
            }
            else ClearCookie(ctx, AuthCookieName);
        }

        CookieOptions CreateAuthCookieOptions(HttpContext ctx, DateTimeOffset? expires = null)
        {
            return new CookieOptions()
            {
                Path = Options.CookieMode == AuthenticationCookieMode.WebFrontPath
                            ? _cookiePath
                            : "/",
                Expires = expires,
                HttpOnly = true,
                Secure = Options.CookieSecurePolicy == CookieSecurePolicy.SameAsRequest
                                ? ctx.Request.IsHttps
                                : Options.CookieSecurePolicy == CookieSecurePolicy.Always
            };
        }

        CookieOptions CreateUnsafeCookieOptions(DateTimeOffset? expires = null)
        {
            return new CookieOptions()
            {
                Path = Options.CookieMode == AuthenticationCookieMode.WebFrontPath
                            ? _cookiePath
                            : "/",
                Secure = false,
                Expires = expires,
                HttpOnly = true
            };
        }

        void ClearCookie(HttpContext ctx, string cookieName)
        {
            ctx.Response.Cookies.Delete(cookieName, cookieName == AuthCookieName
                                                ? CreateAuthCookieOptions(ctx)
                                                : CreateUnsafeCookieOptions());
        }

        #endregion

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
        /// Gets whether <see cref="BasicLoginAsync"/> is supported.
        /// </summary>
        public abstract bool HasBasicLogin { get; }

        /// <summary>
        /// Attempts to login. If it fails, null is returned. <see cref="HasBasicLogin"/> must be true for this
        /// to be called otherwise an <see cref="InvalidOperationException"/> is thrown.
        /// </summary>
        /// <param name="ctx">Current http context.</param>
        /// <param name="userName">The user name.</param>
        /// <param name="password">The password.</param>
        /// <returns>The <see cref="IUserInfo"/> or null.</returns>
        public abstract Task<IUserInfo> BasicLoginAsync( HttpContext ctx, string userName, string password );

        /// <summary>
        /// Gets the existing providers's name.
        /// </summary>
        public abstract IReadOnlyList<string> Providers { get; }

        /// <summary>
        /// Attempts to login a user using an existing provider.
        /// The provider must exist and the payload must be compatible otherwise an <see cref="ArgumentException"/>
        /// is thrown.
        /// </summary>
        /// <param name="ctx">Current http context.</param>
        /// <param name="providerName">The provider name to use.</param>
        /// <param name="payload">The provider dependent login payload.</param>
        /// <returns>The <see cref="IUserInfo"/> or null.</returns>
        public abstract Task<IUserInfo> LoginAsync(HttpContext ctx, string providerName, object payload);
    }

}
