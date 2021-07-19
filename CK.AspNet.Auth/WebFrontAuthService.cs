using CK.Auth;
using CK.Core;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using System.Globalization;
using System.Linq;
using Microsoft.Extensions.DependencyInjection;
using System.Text;

#nullable enable

namespace CK.AspNet.Auth
{
    /// <summary>
    /// Sealed implementation of the actual authentication service.
    /// This implementation is registered as a singleton by <see cref="WebFrontAuthExtensions.AddWebFrontAuth(AuthenticationBuilder)" />.
    /// </summary>
    public sealed class WebFrontAuthService
    {
        /// <summary>
        /// The tag used for logs emitted related to Web Front Authentication or any
        /// authentication related actions.
        /// </summary>
        public static readonly CKTrait WebFrontAuthMonitorTag = ActivityMonitor.Tags.Register( "WebFrontAuth" );

        /// <summary>
        /// Name of the authentication cookie.
        /// </summary>
        public string AuthCookieName { get; }

        /// <summary>
        /// Name of the long term authentication cookie.
        /// </summary>
        public string UnsafeCookieName => AuthCookieName + "LT";

        readonly IAuthenticationTypeSystem _typeSystem;
        readonly IWebFrontAuthLoginService _loginService;

        readonly IDataProtector _genericProtector;
        readonly AuthenticationInfoSecureDataFormat _tokenFormat;
        readonly AuthenticationInfoSecureDataFormat _cookieFormat;
        readonly ExtraDataSecureDataFormat _extraDataFormat;
        readonly string _cookiePath;
        readonly string _bearerHeaderName;
        readonly CookieSecurePolicy _cookiePolicy;
        readonly IOptionsMonitor<WebFrontAuthOptions> _options;
        readonly IWebFrontAuthValidateLoginService? _validateLoginService;
        readonly IWebFrontAuthAutoCreateAccountService? _autoCreateAccountService;
        readonly IWebFrontAuthAutoBindingAccountService? _autoBindingAccountService;
        readonly IWebFrontAuthDynamicScopeProvider? _dynamicScopeProvider;
        readonly IWebFrontAuthValidateAuthenticationInfoService? _validateAuthenticationInfoService;

        /// <summary>
        /// Initializes a new <see cref="WebFrontAuthService"/>.
        /// </summary>
        /// <param name="typeSystem">A <see cref="IAuthenticationTypeSystem"/>.</param>
        /// <param name="loginService">Login service.</param>
        /// <param name="dataProtectionProvider">The data protection provider to use.</param>
        /// <param name="options">Monitored options.</param>
        /// <param name="validateLoginService">Optional service that validates logins.</param>
        /// <param name="autoCreateAccountService">Optional service that enables account creation.</param>
        /// <param name="autoBindingAccountService">Optional service that enables account binding.</param>
        /// <param name="dynamicScopeProvider">Optional service to support scope augmentation.</param>
        /// <param name="validateAuthenticationInfoService">Optional service that is called each time authentication information is restored.</param>
        public WebFrontAuthService(
            IAuthenticationTypeSystem typeSystem,
            IWebFrontAuthLoginService loginService,
            IDataProtectionProvider dataProtectionProvider,
            IOptionsMonitor<WebFrontAuthOptions> options,
            IWebFrontAuthValidateLoginService? validateLoginService = null,
            IWebFrontAuthAutoCreateAccountService? autoCreateAccountService = null,
            IWebFrontAuthAutoBindingAccountService? autoBindingAccountService = null,
            IWebFrontAuthDynamicScopeProvider? dynamicScopeProvider = null,
            IWebFrontAuthValidateAuthenticationInfoService? validateAuthenticationInfoService = null )
        {
            _typeSystem = typeSystem;
            _loginService = loginService;
            _options = options;
            _validateLoginService = validateLoginService;
            _autoCreateAccountService = autoCreateAccountService;
            _autoBindingAccountService = autoBindingAccountService;
            _dynamicScopeProvider = dynamicScopeProvider;
            _validateAuthenticationInfoService = validateAuthenticationInfoService;
            WebFrontAuthOptions initialOptions = CurrentOptions;
            IDataProtector dataProtector = dataProtectionProvider.CreateProtector( typeof( WebFrontAuthHandler ).FullName );
            var cookieFormat = new AuthenticationInfoSecureDataFormat( _typeSystem, dataProtector.CreateProtector( "Cookie", "v1" ) );
            var tokenFormat = new AuthenticationInfoSecureDataFormat( _typeSystem, dataProtector.CreateProtector( "Token", "v1" ) );
            var extraDataFormat = new ExtraDataSecureDataFormat( dataProtector.CreateProtector( "Extra", "v1" ) );
            _genericProtector = dataProtector;
            _cookieFormat = cookieFormat;
            _tokenFormat = tokenFormat;
            _extraDataFormat = extraDataFormat;
            Debug.Assert( WebFrontAuthHandler._cSegmentPath.ToString() == "/c" );
            _cookiePath = initialOptions.EntryPath + "/c/";
            _bearerHeaderName = initialOptions.BearerHeaderName;
            CookieMode = initialOptions.CookieMode;
            _cookiePolicy = initialOptions.CookieSecurePolicy;
            AuthCookieName = initialOptions.AuthCookieName;
        }

        /// <summary>
        /// Gets the cookie mode. This is not a dynamic option: this is the value
        /// captured when this service has been instantiated. 
        /// </summary>
        public AuthenticationCookieMode CookieMode { get; }

        /// <summary>
        /// Direct generation of an authentication token from any <see cref="IAuthenticationInfo"/>.
        /// <see cref="IAuthenticationInfo.CheckExpiration(DateTime)"/> is called with <see cref="DateTime.UtcNow"/>.
        /// This is to be used with caution: the authentication token should never be sent to any client and should be
        /// used only for secure server to server temporary authentication.
        /// The authentication token is signed with the token binding protocol (when on https): it is valid only for the
        /// provided HttpContext.
        /// </summary>
        /// <param name="c">The HttpContext.</param>
        /// <param name="info">The authentication info for which an authentication token must be obtained.</param>
        /// <returns>The url-safe secured authentication token string.</returns>
        public string UnsafeGetAuthenticationToken( HttpContext c, IAuthenticationInfo info )
        {
            if( c == null ) throw new ArgumentNullException( nameof( c ) );
            if( info == null ) throw new ArgumentNullException( nameof( info ) );
            info = info.CheckExpiration();
            return ProtectAuthenticationInfo( c, new FrontAuthenticationInfo( info, false ) );
        }

        /// <summary>
        /// Simple helper that calls <see cref="UnsafeGetAuthenticationToken(HttpContext, IAuthenticationInfo)"/>.
        /// </summary>
        /// <param name="c">The HttpContext.</param>
        /// <param name="userId">The user identifier.</param>
        /// <param name="userName">The user name.</param>
        /// <param name="validity">The validity time span: the shorter the better.</param>
        /// <returns>The url-safe secured authentication token string.</returns>
        public string UnsafeGetAuthenticationToken( HttpContext c, int userId, string userName, TimeSpan validity )
        {
            if( userName == null ) throw new ArgumentNullException( nameof( userName ) );
            var u = _typeSystem.UserInfo.Create( userId, userName );
            var info = _typeSystem.AuthenticationInfo.Create( u, DateTime.UtcNow.Add( validity ) );
            return UnsafeGetAuthenticationToken( c, info );
        }

        /// <summary>
        /// Gets the current options.
        /// This must be used for configurations that can be changed dynamically like <see cref="WebFrontAuthOptions.ExpireTimeSpan"/>
        /// but not for non dynamic ones like <see cref="WebFrontAuthOptions.CookieMode"/>.
        /// </summary>
        internal WebFrontAuthOptions CurrentOptions => _options.Get( WebFrontAuthOptions.OnlyAuthenticationScheme );

        /// <summary>
        /// Gets the monitor from the request service.
        /// Must be called once and only once per request since a new ActivityMonitor is
        /// created when hostBuilder.UseMonitoring() has not been used (the IActivityMonitor is not
        /// available in the context).
        /// </summary>
        /// <param name="c">The http context.</param>
        /// <returns>An activity monitor.</returns>
        IActivityMonitor GetRequestMonitor( HttpContext c )
        {
            return c.RequestServices.GetService<IActivityMonitor>() ?? new ActivityMonitor( "WebFrontAuthService-Request" );
        }

        internal string ProtectAuthenticationInfo( HttpContext c, FrontAuthenticationInfo info )
        {
            Debug.Assert( info.Info != null );
            return _tokenFormat.Protect( info, GetTlsTokenBindingAndServerKey( c ) );
        }

        internal FrontAuthenticationInfo UnprotectAuthenticationInfo( HttpContext c, string data )
        {
            Debug.Assert( data != null );
            return _tokenFormat.Unprotect( data, GetTlsTokenBindingAndServerKey( c ) );
        }

        internal string ProtectExtraData( HttpContext c, IEnumerable<KeyValuePair<string, StringValues>> info )
        {
            Debug.Assert( info != null );
            return _extraDataFormat.Protect( info, GetTlsTokenBindingAndServerKey( c ) );
        }

        internal IEnumerable<KeyValuePair<string, StringValues>> UnprotectExtraData( HttpContext c, string data )
        {
            Debug.Assert( data != null );
            return _extraDataFormat.Unprotect( data, GetTlsTokenBindingAndServerKey( c ) );
        }

        /// <summary>
        /// Handles cached authentication header or calls <see cref="ReadAndCacheAuthenticationHeader"/>.
        /// Never null, can be <see cref="IAuthenticationInfoType.None"/>.
        /// </summary>
        /// <param name="c">The context.</param>
        /// <returns>
        /// The cached or resolved authentication info. 
        /// </returns>
        internal async ValueTask<FrontAuthenticationInfo> EnsureAuthenticationInfoAsync( HttpContext c, IActivityMonitor monitor )
        {
            FrontAuthenticationInfo? authInfo;
            if( c.Items.TryGetValue( typeof( FrontAuthenticationInfo ), out object? o ) )
            {
                authInfo = (FrontAuthenticationInfo)o;
            }
            else
            {
                authInfo = ReadAndCacheAuthenticationHeader( c );
                // If a IWebFrontAuthValidateAuthenticationInfoService is available, calls it.
                // Exceptions are logged but not intercepted here: the request MUST fail!
                if( _validateAuthenticationInfoService != null )
                {
                    try
                    {
                        var vInfo = await _validateAuthenticationInfoService.ValidateAuthenticationInfoAsync( c, monitor, authInfo.Info );
                        if( vInfo == null )
                        {
                            authInfo = new FrontAuthenticationInfo( _typeSystem.AuthenticationInfo.None, false );
                            monitor.Trace( $"The FrontAuthenticationInfo has been set to None by '{_validateAuthenticationInfoService.GetType()}' service." );
                        }
                        else if( vInfo != authInfo.Info )
                        {
                            monitor.Trace( $"The FrontAuthenticationInfo has been modified by '{_validateAuthenticationInfoService.GetType()}' service." );
                            authInfo = new FrontAuthenticationInfo( vInfo, authInfo.RememberMe );
                        }
                    }
                    catch( Exception ex )
                    {
                        monitor.Fatal( $"While calling '{_validateAuthenticationInfoService.GetType()}' service. Exception is rethrown.", ex );
                        throw;
                    }
                }
            }
            return authInfo;
        }

        /// <summary>
        /// Reads authentication header if possible or uses authentication Cookie (and ultimately falls back to 
        /// long term cookie) and caches authentication in request items.
        /// </summary>
        /// <param name="c">The context.</param>
        /// <returns>
        /// The cached or resolved authentication info. 
        /// Never null, can be bound to <see cref="IAuthenticationInfoType.None"/>.
        /// </returns>
        internal FrontAuthenticationInfo ReadAndCacheAuthenticationHeader( HttpContext c )
        {
            Debug.Assert( !c.Items.ContainsKey( typeof( FrontAuthenticationInfo ) ) );
            var monitor = GetRequestMonitor( c );
            bool shouldSetCookies = false;
            FrontAuthenticationInfo fAuth;
            try
            {
                // First try from the bearer: this is always the preferred way.
                string authorization = c.Request.Headers[_bearerHeaderName];
                bool fromBearer = !string.IsNullOrEmpty( authorization )
                              && authorization.StartsWith( "Bearer ", StringComparison.OrdinalIgnoreCase );
                if( fromBearer )
                {
                    Debug.Assert( "Bearer ".Length == 7 );
                    string token = authorization.Substring( 7 ).Trim();
                    fAuth = UnprotectAuthenticationInfo( c, token );
                }
                else
                {
                    // Best case is when we have the authentication cookie, otherwise use the long term cookie.
                    if( CookieMode != AuthenticationCookieMode.None && c.Request.Cookies.TryGetValue( AuthCookieName, out string cookie ) )
                    {
                        fAuth = _cookieFormat.Unprotect( cookie, GetTlsTokenBindingAndServerKey( c ) );
                    }
                    else if( CurrentOptions.UseLongTermCookie && c.Request.Cookies.TryGetValue( UnsafeCookieName, out cookie ) )
                    {
                        var o = JObject.Parse( cookie );
                        // The long term cookie contains a deviceId field.
                        string? deviceId = (string?)o[StdAuthenticationTypeSystem.DeviceIdKeyType];
                        // We may have a "deviceId only" cookie.
                        IUserInfo? info = null;
                        if( o.ContainsKey( StdAuthenticationTypeSystem.UserIdKeyType ) )
                        {
                            info = _typeSystem.UserInfo.FromJObject( o );
                        }
                        var auth = _typeSystem.AuthenticationInfo.Create( info, deviceId: deviceId );
                        // If there is a long term cookie with the user information, then we are "remembering"!
                        // (Checking UserId != 0 here is just to be safe since the anonymous must not "remember").
                        fAuth = new FrontAuthenticationInfo( auth, rememberMe: info != null && info.UserId != 0 );
                    }
                    else
                    {
                        // We have nothing:
                        // - If we could have something (either because CookieMode is AuthenticationCookieMode.RootPath or the request
                        // is inside the /.webfront/c), then we create a new unauthenticated info with a new device identifier.
                        // - If we are outside of the cookie context, we do nothing (otherwise we'll reset the current authentication).
                        if( CookieMode == AuthenticationCookieMode.RootPath
                            || (CookieMode == AuthenticationCookieMode.WebFrontPath
                                && c.Request.Path.Value.StartsWith( _cookiePath, StringComparison.OrdinalIgnoreCase ) ) )
                        {
                            var deviceId = CreateNewDeviceId();
                            var info = _typeSystem.AuthenticationInfo.Create( null, deviceId: deviceId );
                            fAuth = new FrontAuthenticationInfo( info, rememberMe: false );
                            // We set the long lived cookie if possible. The device identifier will be de facto persisted.
                            shouldSetCookies = true;
                        }
                        else
                        {
                            fAuth = new FrontAuthenticationInfo( _typeSystem.AuthenticationInfo.None, rememberMe: false );
                        }
                    }
                }
                if( fAuth == null )
                {
                    monitor.Error( $"Unable to extract a valid authentication information from {(fromBearer ? "Bearer" : "Cookies")}. Resolving to None authentication." );
                    fAuth = new FrontAuthenticationInfo( _typeSystem.AuthenticationInfo.None, false );
                }
                else
                {
                    // Upon each (non anonymous) authentication, when rooted Cookies are used and the SlidingExpiration is on, handles it.
                    if( fAuth.Info.Level >= AuthLevel.Normal && CookieMode == AuthenticationCookieMode.RootPath )
                    {
                        var info = fAuth.Info;
                        TimeSpan slidingExpirationTime = CurrentOptions.SlidingExpirationTime;
                        TimeSpan halfSlidingExpirationTime = new TimeSpan( slidingExpirationTime.Ticks / 2 );
                        if( info.Level >= AuthLevel.Normal
                            && CookieMode == AuthenticationCookieMode.RootPath
                            && halfSlidingExpirationTime > TimeSpan.Zero )
                        {
                            Debug.Assert( info.Expires.HasValue, "Since info.Level >= AuthLevel.Normal." );
                            if( info.Expires.Value <= DateTime.UtcNow + halfSlidingExpirationTime )
                            {
                                fAuth = fAuth.SetInfo( info.SetExpires( DateTime.UtcNow + slidingExpirationTime ) );
                                shouldSetCookies = true;
                            }
                        }
                    }
                    if( shouldSetCookies ) SetCookies( c, fAuth );
                }
            }
            catch( Exception ex )
            {
                monitor.Error( ex );
                fAuth = new FrontAuthenticationInfo( _typeSystem.AuthenticationInfo.None, false );
            }
            c.Items.Add( typeof( FrontAuthenticationInfo ), fAuth );
            return fAuth;
        }

        #region Cookie management

        internal void Logout( HttpContext ctx )
        {
            ClearCookie( ctx, AuthCookieName );
            ClearCookie( ctx, UnsafeCookieName );
        }

        internal void SetCookies( HttpContext ctx, FrontAuthenticationInfo fAuth )
        {
            JObject? longTermCookie = CurrentOptions.UseLongTermCookie ? CreateLongTermCookiePayload( fAuth ) : null;
            if( longTermCookie != null )
            {
                string value = longTermCookie.ToString( Formatting.None );
                ctx.Response.Cookies.Append( UnsafeCookieName, value, CreateUnsafeCookieOptions( DateTime.UtcNow + CurrentOptions.UnsafeExpireTimeSpan ) );
            }
            else ClearCookie( ctx, UnsafeCookieName );

            if( CookieMode != AuthenticationCookieMode.None && fAuth.Info.Level >= AuthLevel.Normal )
            {
                Debug.Assert( fAuth.Info.Expires.HasValue );
                string value = _cookieFormat.Protect( fAuth, GetTlsTokenBindingAndServerKey( ctx ) );
                // If we don't remember, we create a session cookie (no expiration).
                ctx.Response.Cookies.Append( AuthCookieName, value, CreateAuthCookieOptions( ctx, fAuth.RememberMe ? fAuth.Info.Expires : null ) );
            }
            else ClearCookie( ctx, AuthCookieName );
        }

        JObject? CreateLongTermCookiePayload( FrontAuthenticationInfo fAuth )
        {
            bool hasDeviceId = fAuth.Info.DeviceId.Length > 0;
            JObject o;
            if( fAuth.RememberMe && fAuth.Info.UnsafeActualUser.UserId != 0 )
            {
                // The long term cookie stores the unsafe actual user: we are "remembering" so we don't need to store the RememberMe flag.
                o = _typeSystem.UserInfo.ToJObject( fAuth.Info.UnsafeActualUser );
            }
            else if( hasDeviceId )
            {
                // We have no user identifier to remember or have no right to do so, but
                // a device identifier exists: since we are allowed to UseLongTermCookie, then, use it!
                o = new JObject();
            }
            else
            {
                return null;
            }
            if( hasDeviceId )
            {
                o.Add( StdAuthenticationTypeSystem.DeviceIdKeyType, fAuth.Info.DeviceId );
            }
            return o;
        }

        CookieOptions CreateAuthCookieOptions( HttpContext ctx, DateTimeOffset? expires = null )
        {
            return new CookieOptions()
            {
                Path = CookieMode == AuthenticationCookieMode.WebFrontPath
                            ? _cookiePath
                            : "/",
                Expires = expires,
                HttpOnly = true,
                IsEssential = true,
                Secure = _cookiePolicy == CookieSecurePolicy.SameAsRequest
                                ? ctx.Request.IsHttps
                                : _cookiePolicy == CookieSecurePolicy.Always
            };
        }

        CookieOptions CreateUnsafeCookieOptions( DateTimeOffset? expires = null )
        {
            return new CookieOptions()
            {
                Path = CookieMode == AuthenticationCookieMode.WebFrontPath
                            ? _cookiePath
                            : "/",
                Secure = false,
                Expires = expires,
                HttpOnly = true
            };
        }

        void ClearCookie( HttpContext ctx, string cookieName )
        {
            ctx.Response.Cookies.Delete( cookieName, cookieName == AuthCookieName
                                                ? CreateAuthCookieOptions( ctx )
                                                : CreateUnsafeCookieOptions() );
        }

        #endregion

        internal readonly struct LoginResult
        {
            /// <summary>
            /// Standard JSON response.
            /// It is mutable: properties can be appended.
            /// </summary>
            public readonly JObject Response;

            /// <summary>
            /// Can be a None level.
            /// </summary>
            public readonly IAuthenticationInfo Info;

            public LoginResult( JObject r, IAuthenticationInfo a )
            {
                Response = r;
                Info = a;
            }
        }

        /// <summary>
        /// Creates the authentication info, the standard JSON response and sets the cookies.
        /// </summary>
        /// <param name="c">The current Http context.</param>
        /// <param name="u">The user info to login.</param>
        /// <param name="callingScheme">
        /// The calling scheme is used to set a critical expires depending on <see cref="WebFrontAuthOptions.SchemesCriticalTimeSpan"/>.
        /// </param>
        /// <param name="initial">The <see cref="WebFrontAuthLoginContext.InitialAuthentication"/>.</param>
        /// <returns>A login result with the JSON response and authentication info.</returns>
        internal LoginResult HandleLogin( HttpContext c, UserLoginResult u, string callingScheme, IAuthenticationInfo initial, bool rememberMe )
        {
            string deviceId = initial.DeviceId;
            if( deviceId.Length == 0 ) deviceId = CreateNewDeviceId();
            IAuthenticationInfo authInfo;
            if( u.IsSuccess )
            {
                DateTime expires = DateTime.UtcNow + CurrentOptions.ExpireTimeSpan;
                DateTime? criticalExpires = null;
                // Handling Critical level configured for this scheme.
                IDictionary<string, TimeSpan>? scts = CurrentOptions.SchemesCriticalTimeSpan;
                if( scts != null
                    && scts.TryGetValue( callingScheme, out var criticalTimeSpan )
                    && criticalTimeSpan > TimeSpan.Zero )
                {
                    criticalExpires = DateTime.UtcNow + criticalTimeSpan;
                    if( expires < criticalExpires ) expires = criticalExpires.Value;
                }
                authInfo = _typeSystem.AuthenticationInfo.Create( u.UserInfo,
                                                                  expires,
                                                                  criticalExpires,
                                                                  deviceId );
            }
            else
            {
                // With the introduction of the device identifier, authentication info should preserve its
                // device identifier.
                // On authentication failure, we could have kept the current authentication... But this could be misleading
                // for clients: a failed login should fall back to the "anonymous".
                // So we just create a new anonymous authentication (with the same deviceId).
                authInfo = _typeSystem.AuthenticationInfo.Create( null, deviceId : deviceId );
            }
            var fAuth = new FrontAuthenticationInfo( authInfo, rememberMe );
            JObject response = CreateAuthResponse( c, fAuth, refreshable: authInfo.Level >= AuthLevel.Normal && CurrentOptions.SlidingExpirationTime > TimeSpan.Zero, onLogin: u );
            SetCookies( c, fAuth );
            return new LoginResult( response, authInfo );
        }

        /// <summary>
        /// Creates a new device identifier.
        /// If this must be changed, either the IWebFrontAuthLoginService or a new service or
        /// may be the Options may do the job.
        /// </summary>
        /// <returns>The new device identifier.</returns>
        static string CreateNewDeviceId()
        {
            // Uses only url compliant characters and removes the = padding if it exists.
            // Similar to base64url. See https://en.wikipedia.org/wiki/Base64 and https://tools.ietf.org/html/rfc4648.
            return Convert.ToBase64String( Guid.NewGuid().ToByteArray() ).Replace( '+', '-' ).Replace( '/', '_' ).TrimEnd( '=' );
        }

        /// <summary>
        /// Centralized way to return an error: a redirect or a close of the window is emitted.
        /// </summary>
        internal Task SendRemoteAuthenticationError(
            HttpContext c,
            string deviceId,
            string? returnUrl,
            string? callerOrigin,
            string errorId,
            string errorText,
            string? initialScheme = null,
            string? callingScheme = null,
            IEnumerable<KeyValuePair<string, StringValues>>? userData = null,
            UserLoginResult? failedLogin = null )
        {
            if( returnUrl != null )
            {
                Debug.Assert( callerOrigin != null, "Since returnUrl is not null: /c/startLogin has been used." );
                int idxQuery = returnUrl.IndexOf( '?' );
                var path = idxQuery > 0
                            ? returnUrl.Substring( 0, idxQuery )
                            : string.Empty;
                var parameters = idxQuery > 0
                                    ? new QueryString( returnUrl.Substring( idxQuery ) )
                                    : new QueryString();
                parameters = parameters.Add( "errorId", errorId );
                if( !String.IsNullOrWhiteSpace( errorText ) && errorText != errorId )
                {
                    parameters = parameters.Add( "errorText", errorText );
                }
                int loginFailureCode = failedLogin?.LoginFailureCode ?? 0;
                if( loginFailureCode != 0 ) parameters = parameters.Add( "loginFailureCode", loginFailureCode.ToString( CultureInfo.InvariantCulture ) );
                if( initialScheme != null ) parameters = parameters.Add( "initialScheme", initialScheme );
                if( callingScheme != null ) parameters = parameters.Add( "callingScheme", callingScheme );

                var caller = new Uri( callerOrigin );
                var target = new Uri( caller, path + parameters.ToString() );
                c.Response.Redirect( target.ToString() );
                return Task.CompletedTask;
            }
            JObject errObj = CreateErrorAuthResponse( c, deviceId, errorId, errorText, initialScheme, callingScheme, userData, failedLogin );
            return c.Response.WriteWindowPostMessageAsync( errObj, callerOrigin );
        }

        /// <summary>
        /// Creates a JSON response error object.
        /// </summary>
        /// <param name="c">The context.</param>
        /// <param name="errorId">The error identifier.</param>
        /// <param name="errorText">The error text. This can be null (<paramref name="errorId"/> is the key).</param>
        /// <param name="initialScheme">The initial scheme.</param>
        /// <param name="callingScheme">The calling scheme.</param>
        /// <param name="userData">Optional user data (can be null).</param>
        /// <param name="failedLogin">Optional failed login (can be null).</param>
        /// <returns>A {info,token,refreshable} object with error fields inside.</returns>
        internal JObject CreateErrorAuthResponse(
                        HttpContext c,
                        string deviceId,
                        string errorId,
                        string? errorText,
                        string? initialScheme,
                        string? callingScheme,
                        IEnumerable<KeyValuePair<string, StringValues>>? userData,
                        UserLoginResult? failedLogin )
        {
            var response = CreateAuthResponse( c, null, false, failedLogin );
            response.Add( new JProperty( "errorId", errorId ) );
            if( !String.IsNullOrWhiteSpace( errorText ) && errorText != errorId )
            {
                response.Add( new JProperty( "errorText", errorText ) );
            }
            if( initialScheme != null ) response.Add( new JProperty( "initialScheme", initialScheme ) );
            if( callingScheme != null ) response.Add( new JProperty( "callingScheme", callingScheme ) );
            if( userData != null ) response.Add( userData.ToJProperty() );
            return response;
        }

        /// <summary>
        /// Creates a JSON response object.
        /// </summary>
        /// <param name="c">The context.</param>
        /// <param name="fAuth">The authentication info. Null on error!</param>
        /// <param name="refreshable">Whether the info is refreshable or not.</param>
        /// <param name="onLogin">Not null when this response is the result of an actual login (and not a refresh).</param>
        /// <returns>A {info,token,refreshable} object.</returns>
        internal JObject CreateAuthResponse( HttpContext c, FrontAuthenticationInfo? fAuth, bool refreshable, UserLoginResult? onLogin = null )
        {
            var j = new JObject(
                        new JProperty( "info", _typeSystem.AuthenticationInfo.ToJObject( fAuth?.Info ) ),
                        new JProperty( "token", fAuth != null ? ProtectAuthenticationInfo( c, fAuth ) : null ),
                        new JProperty( "refreshable", refreshable ),
                        new JProperty( "rememberMe", fAuth?.RememberMe ?? false ) );
            if( onLogin != null && !onLogin.IsSuccess )
            {
                j.Add( new JProperty( "loginFailureCode", onLogin.LoginFailureCode ) );
                j.Add( new JProperty( "loginFailureReason", onLogin.LoginFailureReason ) );
            }
            return j;
        }

        string? GetTlsTokenBindingAndServerKey( HttpContext c )
        {
            var binding = c.Features.Get<ITlsTokenBindingFeature>()?.GetProvidedTokenBindingId();
            return binding == null ? null : Convert.ToBase64String( binding );
        }

        internal async Task OnHandlerStartLogin( IActivityMonitor m, WebFrontAuthStartLoginContext startContext )
        {
            try
            {
                if( _dynamicScopeProvider != null )
                {
                    startContext.DynamicScopes = await _dynamicScopeProvider.GetScopesAsync( m, startContext );
                }
            }
            catch( Exception ex )
            {
                startContext.SetError( ex.GetType().FullName!, ex.Message ?? "Exception has null message!" );
            }
        }

        /// <summary>
        /// This method fully handles the request.
        /// </summary>
        /// <typeparam name="T">Type of a payload object that is scheme dependent.</typeparam>
        /// <param name="context">The remote authentication ticket.</param>
        /// <param name="payloadConfigurator">
        /// Configurator for the payload object: this action typically populates properties 
        /// from the <see cref="TicketReceivedContext"/> principal claims.
        /// </param>
        /// <returns>The awaitable.</returns>
        public Task HandleRemoteAuthentication<T>( TicketReceivedContext context, Action<T> payloadConfigurator )
        {
            if( context == null ) throw new ArgumentNullException( nameof( context ) );
            if( payloadConfigurator == null ) throw new ArgumentNullException( nameof( payloadConfigurator ) );
            var monitor = GetRequestMonitor( context.HttpContext );

            WebFrontAuthHandler.ExtractClearWFAData( context.Properties,
                                                     out var fRememberMe,
                                                     out var deviceId,
                                                     out var initialScheme,
                                                     out var returnUrl,
                                                     out var callerOrigin );

            // We don't have a "WFA-S" (or "WFA-N" if RememberMe flag is false) for the initialScheme when Authentication Challenge has
            // been called directly: LoginMode is WebFrontAuthLoginMode.None
            // and we steal the context.RedirectUri as being the final redirect url.
            if( initialScheme == null )
            {
                returnUrl = context.ReturnUri;
            }
            context.Properties.Items.TryGetValue( "WFA-C", out var currentAuth );
            context.Properties.Items.TryGetValue( "WFA-D", out var extraData );

            FrontAuthenticationInfo initialAuth = currentAuth == null
                                        ? new FrontAuthenticationInfo( _typeSystem.AuthenticationInfo.Create( null, deviceId: deviceId ), false )
                                        : UnprotectAuthenticationInfo( context.HttpContext, currentAuth );
            List<KeyValuePair<string, StringValues>> userData = extraData == null
                                                                ? new List<KeyValuePair<string, StringValues>>()
                                                                : (List<KeyValuePair<string, StringValues>>)UnprotectExtraData( context.HttpContext, extraData );
            string callingScheme = context.Scheme.Name;
            object payload = _loginService.CreatePayload( context.HttpContext, monitor, callingScheme );
            payloadConfigurator( (T)payload );

            var wfaSC = new WebFrontAuthLoginContext(
                                context.HttpContext,
                                this,
                                _typeSystem,
                                initialScheme != null ? WebFrontAuthLoginMode.StartLogin : WebFrontAuthLoginMode.None,
                                callingScheme,
                                payload,
                                fRememberMe,
                                context.Properties,
                                initialScheme,
                                initialAuth.Info,
                                returnUrl,
                                callerOrigin ?? $"{context.HttpContext.Request.Scheme}://{context.HttpContext.Request.Host}",
                                userData );
            // We always handle the response (we skip the final standard SignIn process).
            context.HandleResponse();

            return UnifiedLogin( monitor, wfaSC, actualLogin =>
            {
                return _loginService.LoginAsync( context.HttpContext, monitor, callingScheme, payload, actualLogin );
            } );
        }

        internal async Task UnifiedLogin( IActivityMonitor monitor, WebFrontAuthLoginContext ctx, Func<bool,Task<UserLoginResult>> logger )
        {
            if( ctx.InitialAuthentication.IsImpersonated )
            {
                ctx.SetError( "LoginWhileImpersonation", "Login is not allowed while impersonation is active." );
                monitor.Error( $"Login is not allowed while impersonation is active: {ctx.InitialAuthentication.ActualUser.UserId} impersonated into {ctx.InitialAuthentication.User.UserId}.", WebFrontAuthMonitorTag );
            }
            UserLoginResult? u = null;
            if( !ctx.HasError )
            {
                // The logger function must kindly return an unlogged UserLoginResult if it cannot log the user in.
                u = await SafeCallLogin( monitor, ctx, logger, actualLogin: _validateLoginService == null );
            }
            if( !ctx.HasError )
            {
                Debug.Assert( u != null );
                int currentlyLoggedIn = ctx.InitialAuthentication.User.UserId;
                if( !u.IsSuccess )
                {
                    // Login failed because user is not registered: entering the account binding or auto registration features.
                    if( u.IsUnregisteredUser )
                    {
                        if( currentlyLoggedIn != 0 )
                        {
                            bool raiseError = true;
                            if( _autoBindingAccountService != null )
                            {
                                UserLoginResult uBound = await _autoBindingAccountService.BindAccountAsync( monitor, ctx );
                                if( uBound != null )
                                {
                                    raiseError = false;
                                    if( !uBound.IsSuccess ) ctx.SetError( uBound );
                                    else
                                    {
                                        if( u != uBound )
                                        {
                                            u = uBound;
                                            monitor.Info( $"[Account.AutoBinding] {currentlyLoggedIn} now bound to '{ctx.CallingScheme}' scheme.", WebFrontAuthMonitorTag );
                                        }
                                    }
                                }
                            }
                            if( raiseError )
                            {
                                ctx.SetError( "Account.NoAutoBinding", "Automatic account binding is disabled." );
                                monitor.Error( $"[Account.NoAutoBinding] {currentlyLoggedIn} tried '{ctx.CallingScheme}' scheme.", WebFrontAuthMonitorTag );
                            }
                        }
                        else
                        {
                            bool raiseError = true;
                            if( _autoCreateAccountService != null )
                            {
                                UserLoginResult uAuto = await _autoCreateAccountService.CreateAccountAndLoginAsync( monitor, ctx );
                                if( uAuto != null )
                                {
                                    raiseError = false;
                                    if( !uAuto.IsSuccess ) ctx.SetError( uAuto );
                                    else u = uAuto;
                                }
                            }
                            if( raiseError )
                            {
                                ctx.SetError( "User.NoAutoRegistration", "Automatic user registration is disabled." );
                                monitor.Error( $"[User.NoAutoRegistration] Automatic user registration is disabled (scheme: {ctx.CallingScheme}).", WebFrontAuthMonitorTag );
                            }
                        }
                    }
                    else
                    {
                        ctx.SetError( u );
                        monitor.Trace( $"[User.LoginError] ({u.LoginFailureCode}) {u.LoginFailureReason}", WebFrontAuthMonitorTag );
                    }
                }
                else
                {
                    // If a validation service is registered, the first call above
                    // did not actually logged the user in (actualLogin = false).
                    // We trigger the real login now if the validation service validates it.
                    if( _validateLoginService != null )
                    {
                        Debug.Assert( u.UserInfo != null );
                        await _validateLoginService.ValidateLoginAsync( monitor, u.UserInfo, ctx );
                        if( !ctx.HasError )
                        {
                            u = await SafeCallLogin( monitor, ctx, logger, actualLogin: true );
                        }
                    }
                }
                // Eventuallly...
                if( !ctx.HasError )
                {
                    Debug.Assert( u != null && u.UserInfo != null, "Login succeeds." );
                    if( currentlyLoggedIn != 0 && u.UserInfo.UserId != currentlyLoggedIn )
                    {
                        monitor.Warn( $"[Account.Relogin] User {currentlyLoggedIn} relogged as {u.UserInfo.UserId} via '{ctx.CallingScheme}' scheme without logout.", WebFrontAuthMonitorTag );
                    }
                    ctx.SetSuccessfulLogin( u );
                    monitor.Info( $"Logged in user {u.UserInfo.UserId} via '{ctx.CallingScheme}'.", WebFrontAuthMonitorTag );
                }
            }
            await ctx.SendResponse();
        }

        /// <summary>
        /// Calls the actual logger function (that must kindly return an unlogged UserLoginResult if it cannot log the user in)
        /// in a try/catch and sets an error on the context only if it it throws.
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="ctx">The login context.</param>
        /// <param name="logger">The actual login function.</param>
        /// <param name="actualLogin">True for an actual login, false otherwise.</param>
        /// <returns>A login result (that mey be unsuccessful).</returns>
        static async Task<UserLoginResult?> SafeCallLogin( IActivityMonitor monitor, WebFrontAuthLoginContext ctx, Func<bool, Task<UserLoginResult>> logger,  bool actualLogin )
        {
            UserLoginResult? u = null;
            try
            {
                u = await logger( actualLogin );
                if( u == null )
                {
                    monitor.Fatal( "Login service returned a null UserLoginResult.", WebFrontAuthMonitorTag );
                    ctx.SetError( "InternalError", "Login service returned a null UserLoginResult." );
                }
            }
            catch( Exception ex )
            {
                monitor.Error( "While calling login service.", ex, WebFrontAuthMonitorTag );
                ctx.SetError( ex );
            }
            return u;
        }
    }
}

