using CK.Auth;
using CK.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace CK.AspNet.Auth
{
    /// <summary>
    /// Handles both a cookie and a token authentication.
    /// This middleware must be added once and only once at the beginning of the pipeline.
    /// </summary>
    public sealed class WebFrontAuthMiddleware : AuthenticationMiddleware<WebFrontAuthMiddlewareOptions>
    {
        const string HeaderValueNoCache = "no-cache";
        const string HeaderValueMinusOne = "-1";
        internal const string CookieName = ".webFront";
        internal const string UnsafeCookieName = ".webFrontLT";

        readonly static PathString _cSegmentPath = "/c";

        readonly WebFrontAuthService _authService;
        readonly PathString _entryPath;
        readonly AuthenticationInfoSecureDataFormat _cookieFormat;
        readonly string _cookiePath;

        /// <summary>
        /// Initializes a new <see cref="WebFrontAuthMiddleware"/>.
        /// </summary>
        /// <param name="next">The next middleware.</param>
        /// <param name="dataProtectionProvider">The data protecion provider.</param>
        /// <param name="loggerFactory">The logger factory.</param>
        /// <param name="urlEncoder">The url encoder.</param>
        /// <param name="authService">The autehntication service.</param>
        /// <param name="options">Middleware options.</param>
        public WebFrontAuthMiddleware(
                RequestDelegate next,
                IDataProtectionProvider dataProtectionProvider,
                ILoggerFactory loggerFactory,
                UrlEncoder urlEncoder,
                WebFrontAuthService authService,
                IOptions<WebFrontAuthMiddlewareOptions> options)
            : base(next, options, loggerFactory, urlEncoder)
        {
            if (dataProtectionProvider == null) throw new ArgumentNullException(nameof(dataProtectionProvider));
            if (authService == null) throw new ArgumentNullException(nameof(authService));
            if( Options.AuthenticationScheme != WebFrontAuthMiddlewareOptions.OnlyAuthenticationScheme )
            {
                throw new ArgumentException( $"Must not be changed.", nameof(Options.AuthenticationScheme));
            }
            _authService = authService;
            var provider = Options.DataProtectionProvider ?? dataProtectionProvider;
            IDataProtector dataProtector = provider.CreateProtector(typeof(WebFrontAuthMiddleware).FullName);
            _cookieFormat = new AuthenticationInfoSecureDataFormat(_authService.AuthenticationTypeSystem, dataProtector.CreateProtector("Cookie", "v1") );
            var tokenFormat = new AuthenticationInfoSecureDataFormat(_authService.AuthenticationTypeSystem, dataProtector.CreateProtector("Token", "v1") );
            _authService.Initialize(_cookieFormat, tokenFormat, Options);
            _entryPath = Options.EntryPath;
            _cookiePath = Options.EntryPath + "/c/";
        }

        class Handler : AuthenticationHandler<WebFrontAuthMiddlewareOptions>
        {
            readonly WebFrontAuthMiddleware _middleware;
            readonly WebFrontAuthService _authService;
            readonly IAuthenticationTypeSystem _typeSystem;

            public Handler(WebFrontAuthMiddleware middleware)
            {
                _middleware = middleware;
                _authService = middleware._authService;
                _typeSystem = _authService.AuthenticationTypeSystem;
            }

            public override Task<bool> HandleRequestAsync()
            {
                PathString remainder;
                if(Request.Path.StartsWithSegments(_middleware._entryPath, out remainder))
                {
                    Response.Headers[HeaderNames.CacheControl] = HeaderValueNoCache;
                    Response.Headers[HeaderNames.Pragma] = HeaderValueNoCache;
                    Response.Headers[HeaderNames.Expires] = HeaderValueMinusOne;
                    Response.StatusCode = StatusCodes.Status404NotFound;
                    if (remainder.StartsWithSegments(_cSegmentPath, StringComparison.Ordinal, out remainder))
                    {
                        if (remainder.Value == "/refresh") return HandleRefresh();
                        else if (remainder.Value == "/basicLogin")
                        {
                            if (_authService.HasBasicLogin)
                            {
                                if (HttpMethods.IsPost(Request.Method)) return BasicLoginAsync();
                                Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
                            }
                        }
                        else if (remainder.Value == "/login")
                        {
                            if (HttpMethods.IsPost(Request.Method)) return ProviderLoginAsync();
                            Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
                        }
                        else if (remainder.Value == "/logout")
                        {
                            return HandleLogout();
                        }
                    }
                    else
                    {
                        if (remainder.Value == "/token") return HandleToken();
                    }
                    return Task.FromResult(true);
                }
                return base.HandleRequestAsync();
            }

            async Task<bool> HandleRefresh()
            {
                // First try is from the bearer: we need to handle the "no cookie at all" case (AuthenticationCookieMode.None).
                IAuthenticationInfo authInfo = _authService.EnsureAuthenticationInfo(Context);
                Debug.Assert(authInfo != null);
                bool refreshable = false;
                if (authInfo.Level >= AuthLevel.Normal && Options.SlidingExpirationTime > TimeSpan.Zero)
                {
                    refreshable = true;
                    DateTime newExp = DateTime.UtcNow + Options.SlidingExpirationTime;
                    if( newExp > authInfo.Expires.Value )
                    {
                        authInfo = authInfo.SetExpires(newExp);
                    }
                }
                JObject response = CreateAuthResponse(authInfo, refreshable);
                if( Request.Query.Keys.Contains("providers") )
                {
                    response.Add("providers", new JArray(_authService.Providers));
                }
                SetCookies(authInfo);
                await WriteResponseAsync(response.ToString(Formatting.None));
                return true;
            }

            Task<bool> HandleToken()
            {
                var info = _authService.EnsureAuthenticationInfo(Context);
                var text = _typeSystem.AuthenticationInfo.ToJObject(info)?.ToString(Formatting.Indented);
                return WriteResponseAsync(text ?? "{}");
            }

            Task<bool> HandleLogout()
            {
                ClearCookie(CookieName);
                if (Request.Query.ContainsKey("full")) ClearCookie(UnsafeCookieName);
                return Task.FromResult(true);
            }


            class ProviderLoginRequest
            {
                public string Provider { get; set; }
                public object Payload { get; set; }
            }

            async Task<bool> ProviderLoginAsync()
            {
                ProviderLoginRequest req = await ReadProviderLoginRequest();
                if (req != null)
                {
                    IUserInfo u = await _authService.LoginAsync( Context, req.Provider, req.Payload);
                    await DoLogin(u);
                }
                return true;
            }

            async Task<ProviderLoginRequest> ReadProviderLoginRequest()
            {
                ProviderLoginRequest req = null;
                try
                {
                    var b = await new StreamReader(Request.Body).ReadToEndAsync();
                    // By using our poor StringMatcher here, we parse the JSON
                    // to basic List<KeyValuePair<string, object>> because 
                    // JObject are IEnumerable<KeyValuePair<string, JToken>> and
                    // KeyValuePair is not covariant. Moreover JToken is not easily 
                    // convertible (to basic types) without using the JToken type.
                    // A dependency on NewtonSoft.Json may not be suitable for some 
                    // providers.
                    var m = new StringMatcher(b);
                    if( m.MatchJSONObject( out object val ) )
                    {
                        var o = val as List<KeyValuePair<string, object>>;
                        if( o != null )
                        {
                            string provider = o.FirstOrDefault(kv => StringComparer.OrdinalIgnoreCase.Equals(kv.Key, "provider")).Value as string;
                            if (!string.IsNullOrWhiteSpace(provider) )
                            {
                                req = new ProviderLoginRequest()
                                {
                                    Provider = provider,
                                    Payload = o.FirstOrDefault(kv => StringComparer.OrdinalIgnoreCase.Equals(kv.Key, "payload")).Value
                                };
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Options.OnError?.Invoke(ex);
                }
                if (req == null) Response.StatusCode = StatusCodes.Status400BadRequest;
                return req;
            }

            #region Basic Authentication support

            class BasicLoginRequest
            {
                public string UserName { get; set; }
                public string Password { get; set; }
            }

            async Task<bool> BasicLoginAsync()
            {
                Debug.Assert(_authService.HasBasicLogin);
                BasicLoginRequest req = await ReadBasicLoginRequest();
                if (req != null)
                {
                    IUserInfo u = await _authService.BasicLoginAsync(Context, req.UserName, req.Password);
                    await DoLogin(u);

                }
                return true;
            }

            async Task<BasicLoginRequest> ReadBasicLoginRequest()
            {
                BasicLoginRequest req = null;
                try
                {
                    var b = await new StreamReader(Request.Body).ReadToEndAsync();
                    var r = JsonConvert.DeserializeObject<BasicLoginRequest>(b);
                    if (!string.IsNullOrWhiteSpace(r.UserName) && !string.IsNullOrWhiteSpace(r.Password)) req = r;
                }
                catch (Exception ex)
                {
                    Options.OnError?.Invoke(ex);
                }
                if (req == null) Response.StatusCode = StatusCodes.Status400BadRequest;
                return req;
            }

            #endregion

            #region Authentication handling.
            protected override Task<AuthenticateResult> HandleAuthenticateAsync()
            {
                IAuthenticationInfo authInfo = _authService.EnsureAuthenticationInfo(Context);
                if (authInfo.IsNullOrNone()) return Task.FromResult(AuthenticateResult.Skip());
                var principal = new ClaimsPrincipal();
                principal.AddIdentity(_typeSystem.AuthenticationInfo.ToClaimsIdentity(authInfo, userInfoOnly:false));
                var ticket = new AuthenticationTicket(principal, new AuthenticationProperties(), Options.AuthenticationScheme);
                return Task.FromResult(AuthenticateResult.Success(ticket));
            }

            #endregion

            Task<bool> DoLogin(IUserInfo u)
            {
                IAuthenticationInfo authInfo = u != null && u.UserId != 0
                                                ? _typeSystem.AuthenticationInfo.Create( u, DateTime.UtcNow + Options.ExpireTimeSpan )
                                                : null;
                JObject response = CreateAuthResponse(authInfo, authInfo != null && Options.SlidingExpirationTime > TimeSpan.Zero);
                SetCookies(authInfo);
                return WriteResponseAsync(response.ToString(Formatting.None), authInfo == null ? StatusCodes.Status401Unauthorized : StatusCodes.Status200OK);
            }

            JObject CreateAuthResponse( IAuthenticationInfo authInfo, bool refreshable )
            {
                return new JObject(
                    new JProperty("info", _typeSystem.AuthenticationInfo.ToJObject(authInfo)),
                    new JProperty("token", authInfo.IsNullOrNone()
                                            ? null
                                            : _authService.CreateToken(Context,authInfo)),
                    new JProperty("refreshable", refreshable) );
            }

            async Task<bool> WriteResponseAsync(string json, int code = StatusCodes.Status200OK)
            {
                Response.StatusCode = code;
                Response.ContentType = "application/json";
                await Response.WriteAsync(json);
                return true;
            }

            void SetCookies(IAuthenticationInfo authInfo)
            {
                if (authInfo != null && Options.UseLongTermCookie && authInfo.UnsafeActualUser.UserId != 0 )
                {
                    string value = _typeSystem.UserInfo.ToJObject( authInfo.UnsafeActualUser ).ToString(Formatting.None);
                    Response.Cookies.Append(UnsafeCookieName, value, CreateUnsafeCookieOptions(DateTime.UtcNow + Options.UnsafeExpireTimeSpan));
                }
                else ClearCookie(UnsafeCookieName);
                if( authInfo != null && Options.CookieMode != AuthenticationCookieMode.None && authInfo.Level >= AuthLevel.Normal)
                {
                    Debug.Assert(authInfo.Expires.HasValue);
                    string value = _middleware._cookieFormat.Protect(authInfo, WebFrontAuthService.GetTlsTokenBinding(Context));
                    Response.Cookies.Append(CookieName, value, CreateAuthCookieOptions(authInfo.Expires));
                }
                else ClearCookie(CookieName);
            }

            CookieOptions CreateAuthCookieOptions(DateTimeOffset? expires = null)
            {
                return new CookieOptions()
                {
                    Path = Options.CookieMode == AuthenticationCookieMode.WebFrontPath
                                ? _middleware._cookiePath
                                : "/",
                    Expires = expires,
                    HttpOnly = true,
                    Secure = Options.CookieSecurePolicy == CookieSecurePolicy.SameAsRequest
                                    ? Request.IsHttps
                                    : Options.CookieSecurePolicy == CookieSecurePolicy.Always
                };
            }

            CookieOptions CreateUnsafeCookieOptions(DateTimeOffset? expires = null)
            {
                return new CookieOptions()
                {
                    Path = _middleware._cookiePath,
                    Secure = false,
                    Expires = expires,
                    HttpOnly = true
                };
            }

            void ClearCookie(string cookieName)
            {
                Response.Cookies.Delete(cookieName, cookieName == CookieName
                                                    ? CreateAuthCookieOptions()
                                                    : CreateUnsafeCookieOptions());
            }

        }

        /// <summary>
        /// Infrastructure.
        /// </summary>
        /// <returns>Returns a new handler.</returns>
        protected override AuthenticationHandler<WebFrontAuthMiddlewareOptions> CreateHandler()
        {
            return new Handler( this );
        }

    }

}
