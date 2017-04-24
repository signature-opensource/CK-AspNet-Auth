using CK.Auth;
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
using System.Diagnostics;
using System.IO;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace CK.AspNet.Auth
{
    public class WebFrontAuthMiddleware : AuthenticationMiddleware<WebFrontAuthMiddlewareOptions>
    {
        const string HeaderValueNoCache = "no-cache";
        const string HeaderValueMinusOne = "-1";
        const string CookieName = ".frontWeb";
        const string UnsafeCookieName = ".frontWebLT";

        readonly static PathString _cSegmentPath = "/c";

        readonly WebFrontAuthService _authService;
        readonly AuthenticationInfoSecureDataFormat _cookieFormat;
        readonly PathString _entryPath;
        readonly string _cookiePath;

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
            var tokenFormat = new AuthenticationInfoSecureDataFormat(_authService.AuthenticationTypeSystem, dataProtector.CreateProtector("Token", "v1") );
            _authService.Initialize(tokenFormat,Options);
            _cookieFormat = new AuthenticationInfoSecureDataFormat(_authService.AuthenticationTypeSystem, dataProtector.CreateProtector("Cookie", "v1") );
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
                    if (remainder.StartsWithSegments(_cSegmentPath, out remainder))
                    {
                        if (remainder.Value == "/refresh") return HandleRefresh();
                        if (remainder.Value == "/basicLogin")
                        {
                            if (_authService.HasBasicLogin)
                            {
                                if (HttpMethods.IsPost(Request.Method)) return BasicLoginAsync();
                                Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
                            }
                        }
                        if (remainder.Value == "/login")
                        {
                            if (HttpMethods.IsPost(Request.Method)) return ProviderLoginAsync();
                            Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
                        }
                        if (remainder.Value == "/logout")
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
                // First try is from the bearer: we need to handle the "no cookie at all" case.
                IAuthenticationInfo authInfo = _authService.EnsureAuthenticationInfo(Context);
                Debug.Assert(authInfo != null);
                if( authInfo.Level == AuthLevel.None )
                {
                    // Best case is when we have the authentication cookie, otherwise use the long term cookie.
                    string cookie;
                    if (Options.UseCookie && Request.Cookies.TryGetValue(CookieName, out cookie))
                    {
                        authInfo = _middleware._cookieFormat.Unprotect(cookie, WebFrontAuthService.GetTlsTokenBinding(Context));
                    }
                    else if (Options.UseLongTermCookie && Request.Cookies.TryGetValue(UnsafeCookieName, out cookie))
                    {
                        IUserInfo info = _typeSystem.UserInfo.FromJObject(JObject.Parse(cookie));
                        authInfo = _typeSystem.AuthenticationInfo.Create(info);
                    }
                }
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
                SetCookies(authInfo);
                await WriteResponseAsync(response.ToString(Formatting.None));
                return true;
            }

            Task<bool> HandleToken()
            {
                var info = _authService.EnsureAuthenticationInfo(Context);
                var text = info != null
                            ? _typeSystem.AuthenticationInfo.ToJObject(info).ToString(Formatting.Indented)
                            : "{}";
                return WriteResponseAsync(text);
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
                    IUserInfo u = await _authService.LoginAsync(req.Provider, req.Payload);
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
                    var r = JsonConvert.DeserializeObject<ProviderLoginRequest>(b);
                    if (!string.IsNullOrWhiteSpace(r.Provider)) req = r;
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
                    IUserInfo u = await _authService.BasicLoginAsync(req.UserName, req.Password);
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
                    Response.Cookies.Append(UnsafeCookieName, value, new CookieOptions()
                    {
                        Path = _middleware._cookiePath,
                        Secure = false,
                        Expires = DateTime.UtcNow + Options.UnsafeExpireTimeSpan,
                        HttpOnly = true
                    });
                }
                else ClearCookie(UnsafeCookieName);
                if( authInfo != null && Options.UseCookie && authInfo.Level >= AuthLevel.Normal)
                {
                    Debug.Assert(authInfo.Expires.HasValue);
                    string value = _middleware._cookieFormat.Protect(authInfo, WebFrontAuthService.GetTlsTokenBinding(Context));
                    Response.Cookies.Append(CookieName, value, new CookieOptions()
                    {
                        Path = _middleware._cookiePath,
                        Expires = authInfo.Expires,
                        HttpOnly = true,
                        Secure = Options.SecurePolicy == CookieSecurePolicy.SameAsRequest
                                    ? Request.IsHttps
                                    : Options.SecurePolicy == CookieSecurePolicy.Always
                    });
                }
                else ClearCookie(CookieName);
            }

            void ClearCookie(string cookieName)
            {
                Response.Cookies.Delete(cookieName, new CookieOptions() { Path = _middleware._cookiePath });
            }

        }

        protected override AuthenticationHandler<WebFrontAuthMiddlewareOptions> CreateHandler()
        {
            return new Handler( this );
        }

    }

}
