using CK.Auth;
using CK.Core;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;

#nullable enable

namespace CK.AspNet.Auth
{
    /// <summary>
    /// Sealed implementation of the actual authentication service.
    /// This implementation is registered as a singleton by <see cref="WebFrontAuthExtensions.AddWebFrontAuth(AuthenticationBuilder)" />,
    /// it is not a <see cref="IAutoService"/> and is a endpoint service (available only from the Global DI).
    /// </summary>
    [EndpointSingletonService]
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

        internal readonly AuthenticationInfoTokenService _tokenService;
        readonly IAuthenticationTypeSystem _typeSystem;
        internal readonly IReadOnlyList<string> _allowedReturnUrls;
        readonly IWebFrontAuthLoginService _loginService;

        readonly FrontAuthenticationInfoSecureDataFormat _cookieFormat;
        readonly ExtraDataSecureDataFormat _extraDataFormat;
        readonly string _cookiePath;
        readonly string _bearerHeaderName;
        readonly CookieSecurePolicy _cookiePolicy;
        /// <summary>
        /// Don't use this directly! Use CurrentOptions property.
        /// </summary>
        readonly IOptionsMonitor<WebFrontAuthOptions> _options;
        readonly IWebFrontAuthValidateLoginService? _validateLoginService;
        readonly IWebFrontAuthAutoCreateAccountService? _autoCreateAccountService;
        readonly IWebFrontAuthAutoBindingAccountService? _autoBindingAccountService;
        readonly IWebFrontAuthImpersonationService? _impersonationService;
        readonly IWebFrontAuthDynamicScopeProvider? _dynamicScopeProvider;

        /// <summary>
        /// Initializes a new <see cref="WebFrontAuthService"/>.
        /// </summary>
        /// <param name="tokenService">The token service (bound to the <see cref="IAuthenticationTypeSystem"/>).</param>
        /// <param name="loginService">Login service.</param>
        /// <param name="options">Monitored options.</param>
        /// <param name="validateLoginService">Optional service that validates logins.</param>
        /// <param name="autoCreateAccountService">Optional service that enables account creation.</param>
        /// <param name="autoBindingAccountService">Optional service that enables account binding.</param>
        /// <param name="dynamicScopeProvider">Optional service to support scope augmentation.</param>
        public WebFrontAuthService( AuthenticationInfoTokenService tokenService,
                                    IAuthenticationTypeSystem typeSystem,
                                    IWebFrontAuthLoginService loginService,
                                    IOptionsMonitor<WebFrontAuthOptions> options,
                                    IWebFrontAuthValidateLoginService? validateLoginService = null,
                                    IWebFrontAuthAutoCreateAccountService? autoCreateAccountService = null,
                                    IWebFrontAuthAutoBindingAccountService? autoBindingAccountService = null,
                                    IWebFrontAuthImpersonationService? impersonationService = null,
                                    IWebFrontAuthDynamicScopeProvider? dynamicScopeProvider = null )
        {
            _tokenService = tokenService;
            _typeSystem = typeSystem;
            _loginService = loginService;
            _options = options;
            _validateLoginService = validateLoginService;
            _autoCreateAccountService = autoCreateAccountService;
            _autoBindingAccountService = autoBindingAccountService;
            _impersonationService = impersonationService;
            _dynamicScopeProvider = dynamicScopeProvider;
            WebFrontAuthOptions initialOptions = CurrentOptions;
            var cookieFormat = new FrontAuthenticationInfoSecureDataFormat( tokenService.TypeSystem, tokenService.BaseDataProtector.CreateProtector( "Cookie", "v1" ) );
            var extraDataFormat = new ExtraDataSecureDataFormat( tokenService.BaseDataProtector.CreateProtector( "Extra", "v1" ) );
            _cookieFormat = cookieFormat;
            _extraDataFormat = extraDataFormat;
            Debug.Assert( WebFrontAuthHandler._cSegmentPath.ToString() == "/c" );
            _cookiePath = initialOptions.EntryPath + "/c/";
            _bearerHeaderName = initialOptions.BearerHeaderName;
            CookieMode = initialOptions.CookieMode;
            _cookiePolicy = initialOptions.CookieSecurePolicy;
            AuthCookieName = initialOptions.AuthCookieName;
            _allowedReturnUrls = initialOptions.AllowedReturnUrls.ToArray();
        }

        /// <summary>
        /// Gets the cookie mode. This is not a dynamic option: this is the value
        /// captured when this service has been instantiated. 
        /// </summary>
        public AuthenticationCookieMode CookieMode { get; }

        /// <summary>
        /// Result for the <see cref="BasicLoginCommandAsync(IActivityMonitor, HttpContext, string, string, TimeSpan?, TimeSpan?, bool)"/>.
        /// </summary>
        public sealed class BasicLoginCommandResult
        {
            internal BasicLoginCommandResult( IAuthenticationInfo? info, string? token, string? errorId, string? errorText )
            {
                Throw.DebugAssert( (info == null) == (token == null) );
                Throw.DebugAssert( (info == null) != (errorId == null) );
                Throw.DebugAssert( "errorText => errorId", errorText == null || errorId != null );
                Info = info;
                Token = token;
                ErrorId = errorId;
                if( errorId != null && errorText == null ) errorText = string.Empty; 
                ErrorText = errorText;
            }

            /// <summary>
            /// Gets whether the login succeeded.
            /// </summary>
            [MemberNotNullWhen( true, nameof( Info ), nameof( Token ) )]
            [MemberNotNullWhen( false, nameof( ErrorId ), nameof( ErrorText ) )]
            public bool Success => Info != null;

            /// <summary>
            /// Gets the non null authentication info on success.
            /// </summary>
            public IAuthenticationInfo? Info { get; }

            /// <summary>
            /// Gets the non null token on success.
            /// </summary>
            public string? Token { get; }

            /// <summary>
            /// Gets a non null error identifier if <see cref="Success"/> is false.
            /// </summary>
            public string? ErrorId { get; }

            /// <summary>
            /// Gets a non null error text (possibly empty) if <see cref="Success"/> is false.
            /// </summary>
            public string? ErrorText { get; }
        }

        /// <summary>
        /// Attempts to login a user by its name/password.
        /// <see cref="IWebFrontAuthLoginService.HasBasicLogin"/> must be true otherwise an <see cref="InvalidOperationException"/> is thrown.
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="httpContext">The current http context.</param>
        /// <param name="userName">The user name.</param>
        /// <param name="password">The password.</param>
        /// <param name="impersonateActualUser">Wether the </param>
        /// <param name="duration"></param>
        /// <param name="criticalDuration"></param>
        /// <returns>The login result.</returns>
        public async Task<BasicLoginCommandResult> BasicLoginCommandAsync( IActivityMonitor monitor,
                                                                           HttpContext httpContext,
                                                                           string userName,
                                                                           string password,
                                                                           TimeSpan? duration = null,
                                                                           TimeSpan? criticalDuration = null,
                                                                           bool impersonateActualUser = false )
        {
            Throw.CheckState( _loginService.HasBasicLogin );
            Throw.CheckNotNullArgument( monitor );
            Throw.CheckNotNullArgument( httpContext );
            Throw.CheckNotNullArgument( userName );
            Throw.CheckNotNullArgument( password );

            var current = EnsureAuthenticationInfo( httpContext, ref monitor );
            var ctx = new WebFrontAuthLoginContext( httpContext,
                                                    this,
                                                    _typeSystem,
                                                    WebFrontAuthLoginMode.BasicLogin,
                                                    "Basic",
                                                    Tuple.Create( userName, password ),
                                                    authProps: null,
                                                    initialScheme: "Basic",
                                                    current,
                                                    impersonateActualUser,
                                                    returnUrl: null,
                                                    callerOrigin: null,
                                                    new Dictionary<string, string?>() );

            if( CheckLoginWhileImpersonation( monitor, current.Info, impersonateActualUser, ctx ) )
            {
                await DoUnifiedLoginAsync( monitor, ctx, actualLogin =>
                {
                    return _loginService.BasicLoginAsync( httpContext, monitor, userName, password, actualLogin );
                } );
            }
            if( ctx.HasError )
            {
                return new BasicLoginCommandResult( null, null, ctx._errorId, ctx._errorText );
            }
            Throw.DebugAssert( ctx._successfulLogin != null );
            var fAuth = await HandleLoginCoreAsync( httpContext,
                                                    monitor,
                                                    ctx._successfulLogin,
                                                    "Basic",
                                                    initial: current.Info,
                                                    false,
                                                    impersonateActualUser,
                                                    duration,
                                                    criticalDuration );
            var token = _tokenService.UnsafeCreateAuthenticationToken( fAuth.Info );
            return new BasicLoginCommandResult( fAuth.Info, token, null, null );
        }

        /// <summary>
        /// Log out by clearing the cookies.
        /// </summary>
        /// <param name="ctx">The current Http context.</param>
        /// <returns>The awaitable.</returns>
        public Task LogoutCommandAsync( IActivityMonitor monitor, HttpContext ctx )
        {
            FrontAuthenticationInfo fAuth = EnsureAuthenticationInfo( ctx, ref monitor );
            if( fAuth.Info.Level != AuthLevel.None )
            {
                monitor.Info( WebFrontAuthMonitorTag, $"User '{fAuth.Info.ActualUser.UserName} ({fAuth.Info.ActualUser.UserId})' logged out." );
            }
            ClearCookie( ctx, AuthCookieName );
            ClearCookie( ctx, UnsafeCookieName );
            return Task.CompletedTask;
        }

        /// <summary>
        /// Refreshes the current authentication
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="httpContext">The current http context.</param>
        /// <param name="callBackend">Whether the <see cref="IWebFrontAuthLoginService.RefreshAuthenticationInfoAsync"/> must be called.</param>
        /// <returns>The authentication info and the token.</returns>
        public async Task<(IAuthenticationInfo Info, string Token)> RefreshCommandAsync( IActivityMonitor monitor,
                                                                                         HttpContext httpContext,
                                                                                         bool callBackend = false )
        {
            (var fAuth, _) = await RefreshInfoAsync( httpContext, monitor, callBackend );
            ApplySlidingExpirationAndSetCookies( httpContext, ref fAuth );
            return (fAuth.Info, _tokenService.UnsafeCreateAuthenticationToken( fAuth.Info ));
        }

        internal async Task<(FrontAuthenticationInfo,IActivityMonitor?)> RefreshInfoAsync( HttpContext ctx, IActivityMonitor? monitor, bool callBackend )
        {
            FrontAuthenticationInfo fAuth = EnsureAuthenticationInfo( ctx, ref monitor );
            Debug.Assert( fAuth != null );
            if( CurrentOptions.AlwaysCallBackendOnRefresh || callBackend )
            {
                var newExpires = DateTime.UtcNow + CurrentOptions.ExpireTimeSpan;
                monitor ??= GetRequestMonitor( ctx );
                fAuth = fAuth.SetInfo( await _loginService.RefreshAuthenticationInfoAsync( ctx, monitor, fAuth.Info, newExpires ) );
            }
            return (fAuth,monitor);
        }

        internal bool ApplySlidingExpirationAndSetCookies( HttpContext httpContext, ref FrontAuthenticationInfo fAuth )
        {
            var authInfo = fAuth.Info;
            bool refreshable = false;
            TimeSpan slidingExpirationTime = CurrentOptions.SlidingExpirationTime;
            if( authInfo.Level >= AuthLevel.Normal && slidingExpirationTime > TimeSpan.Zero )
            {
                Debug.Assert( authInfo.Expires != null );
                refreshable = true;
                DateTime newExp = DateTime.UtcNow + slidingExpirationTime;
                if( newExp > authInfo.Expires.Value )
                {
                    fAuth = fAuth.SetInfo( authInfo.SetExpires( newExp ) );
                }
            }
            SetCookies( httpContext, fAuth );
            return refreshable;
        }


        /// <summary>
        /// Direct generation of an authentication token from any <see cref="IAuthenticationInfo"/>.
        /// <see cref="IAuthenticationInfo.CheckExpiration(DateTime)"/> is called with <see cref="DateTime.UtcNow"/>.
        /// This is to be used with caution: the authentication token should never be sent to any client and should be
        /// used only for secure server to server temporary authentication.
        /// </summary>
        /// <param name="c">The HttpContext.</param>
        /// <param name="info">The authentication info for which an authentication token must be obtained.</param>
        /// <returns>The url-safe secured authentication token string.</returns>
        [Obsolete( "Please use the AuthenticationInfoTokenService.UnsafeCreateAuthenticationToken method instead.", true )]
        public string UnsafeGetAuthenticationToken( HttpContext c, IAuthenticationInfo info )
        {
            if( c == null ) throw new ArgumentNullException( nameof( c ) );
            return _tokenService.UnsafeCreateAuthenticationToken( info );
        }

        /// <summary>
        /// Simple helper that calls <see cref="UnsafeGetAuthenticationToken(HttpContext, IAuthenticationInfo)"/>.
        /// </summary>
        /// <param name="c">The HttpContext.</param>
        /// <param name="userId">The user identifier.</param>
        /// <param name="userName">The user name.</param>
        /// <param name="validity">The validity time span: the shorter the better.</param>
        /// <returns>The url-safe secured authentication token string.</returns>
        [Obsolete( "Please use the AuthenticationInfoTokenService.UnsafeCreateAuthenticationToken method instead.", true )]
        public string UnsafeGetAuthenticationToken( HttpContext c, int userId, string userName, TimeSpan validity )
        {
            if( userName == null ) throw new ArgumentNullException( nameof( userName ) );
            var u = _tokenService.TypeSystem.UserInfo.Create( userId, userName );
            var info = _tokenService.TypeSystem.AuthenticationInfo.Create( u, DateTime.UtcNow.Add( validity ) );
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

        internal string ProtectExtraData( IDictionary<string, string?> info )
        {
            Debug.Assert( info != null );
            return _extraDataFormat.Protect( info );
        }

        internal IDictionary<string, string?> UnprotectExtraData( string data )
        {
            Debug.Assert( data != null );
            return _extraDataFormat.Unprotect( data )!;
        }

        internal void SetWFAData( AuthenticationProperties p,
                                  FrontAuthenticationInfo fAuth,
                                  bool impersonateActualUser,
                                  string? initialScheme,
                                  string? callerOrigin,
                                  string? returnUrl,
                                  IDictionary<string, string?> userData )
        {
            p.Items.Add( "WFA2C", _tokenService.ProtectFrontAuthenticationInfo( fAuth ) );
            if( !String.IsNullOrWhiteSpace( initialScheme ) )
            {
                p.Items.Add( "WFA2S", initialScheme );
            }
            if( !String.IsNullOrWhiteSpace( callerOrigin ) )
            {
                p.Items.Add( "WFA2O", callerOrigin );
            }
            if( returnUrl != null )
            {
                p.Items.Add( "WFA2R", returnUrl );
            }
            if( userData.Count != 0 )
            {
                p.Items.Add( "WFA2D", ProtectExtraData( userData ) );
            }
            if( impersonateActualUser )
            {
                p.Items.Add( "WFA2I", "" );
            }
        }

        internal void GetWFAData( HttpContext h,
                                  AuthenticationProperties properties,
                                  out FrontAuthenticationInfo fAuth,
                                  out bool impersonateActualUser,
                                  out string? initialScheme,
                                  out string? callerOrigin,
                                  out string? returnUrl,
                                  out IDictionary<string, string?> userData )
        {
            fAuth = GetFrontAuthenticationInfo( h, properties );
            properties.Items.TryGetValue( "WFA2S", out initialScheme );
            properties.Items.TryGetValue( "WFA2O", out callerOrigin );
            properties.Items.TryGetValue( "WFA2R", out returnUrl );
            if( properties.Items.TryGetValue( "WFA2D", out var sUData ) && sUData != null )
            {
                userData = UnprotectExtraData( sUData );
            }
            else
            {
                userData = new Dictionary<string, string?>();
            }
            impersonateActualUser = properties.Items.ContainsKey( "WFA2I" );
        }

        internal FrontAuthenticationInfo GetFrontAuthenticationInfo( HttpContext h, AuthenticationProperties properties )
        {
            if( !h.Items.TryGetValue( typeof( RemoteAuthenticationEventsContextExtensions ), out var fAuth ) )
            {
                if( properties.Items.TryGetValue( "WFA2C", out var currentAuth ) )
                {
                    Debug.Assert( currentAuth != null );
                    fAuth = _tokenService.UnprotectFrontAuthenticationInfo( currentAuth );
                }
                else
                {
                    // There should always be the WFA2C key in Authentication properties.
                    // However if it's not here, we return the AuthenticationType.None that has an empty DeviceId.
                    fAuth = _tokenService.TypeSystem.AuthenticationInfo.None;
                }
                h.Items.Add( typeof( RemoteAuthenticationEventsContextExtensions ), fAuth );
            }
            Debug.Assert( fAuth != null );  
            return (FrontAuthenticationInfo)fAuth;
        }

        /// <summary>
        /// Handles cached authentication header or calls ReadAndCacheAuthenticationHeader.
        /// Never null, can be <see cref="IAuthenticationInfoType.None"/>.
        /// </summary>
        /// <param name="c">The context.</param>
        /// <param name="monitor">The request monitor if it's available. Will be obtained if required.</param>
        /// <returns>
        /// The cached or resolved authentication info. 
        /// </returns>
        internal FrontAuthenticationInfo EnsureAuthenticationInfo( HttpContext c, [NotNullIfNotNull("monitor")]ref IActivityMonitor? monitor )
        {
            FrontAuthenticationInfo? authInfo;
            if( c.Items.TryGetValue( typeof( FrontAuthenticationInfo ), out object? o ) )
            {
                authInfo = (FrontAuthenticationInfo)o!;
            }
            else
            {
                authInfo = ReadAndCacheAuthenticationHeader( c, ref monitor );
            }
            return authInfo;
        }

        /// <summary>
        /// Reads authentication header if possible or uses authentication Cookie (and ultimately falls back to 
        /// long term cookie) and caches authentication in request items.
        /// </summary>
        /// <param name="c">The context.</param>
        /// <param name="monitor">The request monitor if it's available. Will be obtained if required.</param>
        /// <returns>
        /// The front authentication info. 
        /// </returns>
        internal FrontAuthenticationInfo ReadAndCacheAuthenticationHeader( HttpContext c, ref IActivityMonitor? monitor )
        {
            Debug.Assert( !c.Items.ContainsKey( typeof( FrontAuthenticationInfo ) ) );
            bool shouldSetCookies = false;
            FrontAuthenticationInfo? fAuth = null;
            // First try from the bearer: this is always the preferred way.
            string authorization = c.Request.Headers[_bearerHeaderName];
            bool fromBearer = !string.IsNullOrEmpty( authorization )
                              && authorization.StartsWith( "Bearer ", StringComparison.OrdinalIgnoreCase );
            if( fromBearer )
            {
                try
                {
                    Debug.Assert( "Bearer ".Length == 7 );
                    string token = authorization.Substring( 7 ).Trim();
                    fAuth = _tokenService.UnprotectFrontAuthenticationInfo( token );
                }
                catch( Exception ex )
                {
                    monitor ??= GetRequestMonitor( c );
                    monitor.Error( "While reading bearer.", ex );
                }
            }
            if( fAuth == null )
            {
                // Best case is when we have the authentication cookie, otherwise use the long term cookie.
                if( CookieMode != AuthenticationCookieMode.None && c.Request.Cookies.TryGetValue( AuthCookieName, out string cookie ) )
                {
                    try
                    {
                        fAuth = _cookieFormat.Unprotect( cookie );
                    }
                    catch( Exception ex )
                    {
                        monitor ??= GetRequestMonitor( c );
                        monitor.Error( "While reading Cookie.", ex );
                    }
                }
                if( fAuth == null )
                {
                    if( CurrentOptions.UseLongTermCookie && c.Request.Cookies.TryGetValue( UnsafeCookieName, out cookie ) )
                    {
                        try
                        {
                            var o = JObject.Parse( cookie );
                            // The long term cookie contains a deviceId field.
                            string? deviceId = (string?)o[StdAuthenticationTypeSystem.DeviceIdKeyType];
                            // We may have a "deviceId only" cookie.
                            IUserInfo? info = null;
                            if( o.ContainsKey( StdAuthenticationTypeSystem.UserIdKeyType ) )
                            {
                                info = _tokenService.TypeSystem.UserInfo.FromJObject( o );
                            }
                            var auth = _tokenService.TypeSystem.AuthenticationInfo.Create( info, deviceId: deviceId );
                            Debug.Assert( auth.Level < AuthLevel.Normal, "No expiration is an Unsafe authentication." );
                            // If there is a long term cookie with the user information, then we are "remembering"!
                            // (Checking UserId != 0 here is just to be safe since the anonymous must not "remember").
                            fAuth = new FrontAuthenticationInfo( auth, rememberMe: info != null && info.UserId != 0 );
                        }
                        catch( Exception ex )
                        {
                            monitor ??= GetRequestMonitor( c );
                            monitor.Error( "While reading Long Term Cookie.", ex );
                        }
                    }
                    if( fAuth == null )
                    {
                        // We have nothing or only errors:
                        // - If we could have something (either because CookieMode is AuthenticationCookieMode.RootPath or the request
                        // is inside the /.webfront/c), then we create a new unauthenticated info with a new device identifier.
                        // - If we are outside of the cookie context, we do nothing (otherwise we'll reset the current authentication).
                        if( CookieMode == AuthenticationCookieMode.RootPath
                            || (CookieMode == AuthenticationCookieMode.WebFrontPath
                                && c.Request.Path.Value.StartsWith( _cookiePath, StringComparison.OrdinalIgnoreCase )) )
                        {
                            var deviceId = CreateNewDeviceId();
                            var auth = _tokenService.TypeSystem.AuthenticationInfo.Create( null, deviceId: deviceId );
                            fAuth = new FrontAuthenticationInfo( auth, rememberMe: false );
                            Debug.Assert( auth.Level < AuthLevel.Normal, "No expiration is an Unsafe authentication." );
                            // We set the long lived cookie if possible. The device identifier will be de facto persisted.
                            shouldSetCookies = true;
                        }
                        else
                        {
                            fAuth = new FrontAuthenticationInfo( _tokenService.TypeSystem.AuthenticationInfo.None, rememberMe: false );
                        }
                    }
                }
            }
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
            c.Items.Add( typeof( FrontAuthenticationInfo ), fAuth );
            return fAuth;
        }

        #region Cookie management

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
                string value = _cookieFormat.Protect( fAuth );
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
                o = _tokenService.TypeSystem.UserInfo.ToJObject( fAuth.Info.UnsafeActualUser );
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
        /// Note that the <see cref="FrontAuthenticationInfo"/> is updated in the <see cref="HttpContext.Items"/>.
        /// </summary>
        /// <param name="c">The current Http context.</param>
        /// <param name="u">The user info to login.</param>
        /// <param name="callingScheme">
        /// The calling scheme is used to set a critical expires depending on <see cref="WebFrontAuthOptions.SchemesCriticalTimeSpan"/>.
        /// </param>
        /// <param name="initial">The <see cref="WebFrontAuthLoginContext.InitialAuthentication"/>.</param>
        /// <param name="impersonateActualUser">True to impersonate the current actor.</param>
        /// <returns>A login result with the JSON response and authentication info.</returns>
        internal async ValueTask<LoginResult> HandleLoginAsync( HttpContext c,
                                                                IActivityMonitor monitor,
                                                                UserLoginResult u,
                                                                string callingScheme,
                                                                IAuthenticationInfo initial,
                                                                bool rememberMe,
                                                                bool impersonateActualUser )
        {
            FrontAuthenticationInfo fAuth = await HandleLoginCoreAsync( c, monitor, u, callingScheme, initial, rememberMe, impersonateActualUser );
            JObject response = CreateAuthResponse( c, refreshable: fAuth.Info.Level >= AuthLevel.Normal && CurrentOptions.SlidingExpirationTime > TimeSpan.Zero,
                                                      fAuth,
                                                      onLogin: u );
            return new LoginResult( response, fAuth.Info );
        }

        async ValueTask<FrontAuthenticationInfo> HandleLoginCoreAsync( HttpContext c,
                                                                       IActivityMonitor monitor,
                                                                       UserLoginResult u,
                                                                       string callingScheme,
                                                                       IAuthenticationInfo initial,
                                                                       bool rememberMe,
                                                                       bool impersonateActualUser,
                                                                       TimeSpan? expiresTimeSpan = null,
                                                                       TimeSpan? criticalExpiresTimeSpan = null )
        {
            string deviceId = initial.DeviceId;
            if( deviceId.Length == 0 ) deviceId = CreateNewDeviceId();
            IAuthenticationInfo authInfo;
            if( u.IsSuccess )
            {
                DateTime expires = DateTime.UtcNow + (expiresTimeSpan ?? CurrentOptions.ExpireTimeSpan);
                DateTime? criticalExpires = null;
                if( criticalExpiresTimeSpan.HasValue ) criticalExpires = DateTime.UtcNow + criticalExpiresTimeSpan.Value;
                else
                {
                    // Handling Critical level configured for this scheme.
                    IDictionary<string, TimeSpan>? scts = CurrentOptions.SchemesCriticalTimeSpan;
                    if( scts != null
                        && scts.TryGetValue( callingScheme, out var criticalTimeSpan )
                        && criticalTimeSpan > TimeSpan.Zero )
                    {
                        criticalExpires = DateTime.UtcNow + criticalTimeSpan;
                        if( expires < criticalExpires ) expires = criticalExpires.Value;
                    }
                }
                authInfo = _tokenService.TypeSystem.AuthenticationInfo.Create( u.UserInfo,
                                                                                expires,
                                                                                criticalExpires,
                                                                                deviceId );
                // If there is no _impersonationService or if the user impersonates hiself, we do nothing:
                // this de facto resets any impersonation.
                if( impersonateActualUser
                    && _impersonationService != null
                    && initial.ActualUser.UserId != 0
                    && initial.ActualUser.UserId != u.UserInfo.UserId )
                {
                    IUserInfo? target = null;
                    try
                    {
                        target = await _impersonationService.ImpersonateAsync( c, monitor, authInfo, initial.ActualUser.UserId );
                    }
                    catch( Exception ex )
                    {
                        monitor.Error( WebFrontAuthMonitorTag, $"Error while calling 'IWebFrontAuthImpersonationService.ImpersonateAsync()'.", ex );
                    }
                    if( target != null )
                    {
                        authInfo = authInfo.Impersonate( target );
                        monitor.Info( WebFrontAuthMonitorTag, $"User '{authInfo.ActualUser.UserName} ({authInfo.ActualUser.UserId})' logged in and is impersonating '{target.UserName} ({target.UserId})'." );
                    }
                    else
                    {
                        monitor.Warn( WebFrontAuthMonitorTag, $"Rejected impersonation for newly logged in '{authInfo.ActualUser.UserName} ({authInfo.ActualUser.UserId})' " +
                            $"into '{initial.ActualUser.UserName} ({initial.ActualUser.UserId})'." );
                    }
                }
            }
            else
            {
                // With the introduction of the device identifier, authentication info should preserve its
                // device identifier.
                // On authentication failure, we could have kept the current authentication... But this could be misleading
                // for clients: a failed login should fall back to the "anonymous".
                // So we just create a new anonymous authentication (with the same deviceId).
                authInfo = _tokenService.TypeSystem.AuthenticationInfo.Create( null, deviceId: deviceId );
            }
            var fAuth = new FrontAuthenticationInfo( authInfo, rememberMe );
            c.Items[typeof( FrontAuthenticationInfo )] = fAuth;
            SetCookies( c, fAuth );
            return fAuth;
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
        internal Task SendRemoteAuthenticationErrorAsync( HttpContext c,
                                                          FrontAuthenticationInfo fAuth,
                                                          string? returnUrl,
                                                          string? callerOrigin,
                                                          string errorId,
                                                          string errorText,
                                                          string? initialScheme = null,
                                                          string? callingScheme = null,
                                                          IDictionary<string, string?>? userData = null,
                                                          UserLoginResult? failedLogin = null )
        {
            if( returnUrl != null )
            {
                Debug.Assert( callerOrigin == null, "Since returnUrl is not null: /c/startLogin has been used without callerOrigin." );
                int idxQuery = returnUrl.IndexOf( '?' );
                var path = idxQuery > 0
                            ? returnUrl.Substring( 0, idxQuery )
                            : returnUrl;
                var parameters = idxQuery > 0
                                    ? new QueryString( returnUrl.Substring( idxQuery ) )
                                    : new QueryString();
                parameters = parameters.Add( "errorId", errorId );
                if( !String.IsNullOrWhiteSpace( errorText ) && errorText != errorId )
                {
                    parameters = parameters.Add( "errorText", errorText );
                }
                // UnsafeActualUser must be removed.
                // A ActualLevel must be added.
                //  => SetLevel(): if !impersonated => both changed.
                //                 if impersonated => Level is set at most to the ActualLevel.
                //  => SetActualLevel(): if !impersonated => both changed.
                //                       if impersonated => Sets the actual level.
                //                       Level is clamped to be at most the ActualLevel.
                //
                // 
                // if( fAuth.Info.ActualLevel <= AuthLevel.Unsafe ) ??
                // {
                //    // Need a /c/downgradeLevel entry point ? (but we have it: Logout is downgrade to None + forget deviceId...)
                //    // "forget deviceId" on None should be in the WebFrontAuthOption...
                //
                //    parameters = parameters.Add( "wfaAuthLevel", fAuth.Info.ActualLevel );
                // }
                int loginFailureCode = failedLogin?.LoginFailureCode ?? 0;
                if( loginFailureCode != 0 ) parameters = parameters.Add( "loginFailureCode", loginFailureCode.ToString( CultureInfo.InvariantCulture ) );
                if( initialScheme != null ) parameters = parameters.Add( "initialScheme", initialScheme );
                if( callingScheme != null ) parameters = parameters.Add( "callingScheme", callingScheme );

                var target = new Uri( path + parameters.ToString() );
                c.Response.Redirect( target.ToString() );
                return Task.CompletedTask;
            }
            Debug.Assert( callerOrigin != null, "Since returnUrl is null /c/startLogin has callerOrigin." );
            JObject errObj = CreateErrorAuthResponse( c, fAuth, errorId, errorText, initialScheme, callingScheme, userData, failedLogin );
            return c.Response.WriteWindowPostMessageAsync( errObj, callerOrigin );
        }

        /// <summary>
        /// Creates a JSON response error object.
        /// </summary>
        /// <param name="c">The context.</param>
        /// <param name="fAuth">
        /// The current authentication info or a TypeSystem.AuthenticationInfo.None
        /// info (with a device identifier if possible).
        /// </param>
        /// <param name="errorId">The error identifier.</param>
        /// <param name="errorText">The error text. This can be null (<paramref name="errorId"/> is the key).</param>
        /// <param name="initialScheme">The initial scheme.</param>
        /// <param name="callingScheme">The calling scheme.</param>
        /// <param name="userData">Optional user data (can be null).</param>
        /// <param name="failedLogin">Optional failed login (can be null).</param>
        /// <returns>A {info,token,refreshable} object with error fields inside.</returns>
        internal JObject CreateErrorAuthResponse( HttpContext c,
                                                  FrontAuthenticationInfo fAuth,
                                                  string errorId,
                                                  string? errorText,
                                                  string? initialScheme,
                                                  string? callingScheme,
                                                  IDictionary<string, string?>? userData,
                                                  UserLoginResult? failedLogin )
        {
            var response = CreateAuthResponse( c, false, fAuth, failedLogin );
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
        /// <param name="refreshable">Whether the info is refreshable or not.</param>
        /// <param name="fAuth">
        /// The authentication info.
        /// It is never null, even on error: it must be the current authentication info or a TypeSystem.AuthenticationInfo.None
        /// info (with a device identifier if possible).
        /// </param>
        /// <param name="onLogin">Not null when this response is the result of an actual login (and not a refresh).</param>
        /// <returns>A {info,token,refreshable} object.</returns>
        internal JObject CreateAuthResponse( HttpContext c, bool refreshable, FrontAuthenticationInfo fAuth, UserLoginResult? onLogin = null )
        {
            var j = new JObject(
                        new JProperty( "info", _tokenService.TypeSystem.AuthenticationInfo.ToJObject( fAuth.Info ) ),
                        new JProperty( "token", _tokenService.ProtectFrontAuthenticationInfo( fAuth ) ),
                        new JProperty( "refreshable", refreshable ),
                        new JProperty( "rememberMe", fAuth.RememberMe ) );
            if( onLogin != null && !onLogin.IsSuccess )
            {
                j.Add( new JProperty( "loginFailureCode", onLogin.LoginFailureCode ) );
                j.Add( new JProperty( "loginFailureReason", onLogin.LoginFailureReason ) );
            }
            return j;
        }

        internal async Task OnHandlerStartLoginAsync( IActivityMonitor m, WebFrontAuthStartLoginContext startContext )
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
        public Task HandleRemoteAuthenticationAsync<T>( TicketReceivedContext context, Action<T> payloadConfigurator )
        {
            if( context == null ) throw new ArgumentNullException( nameof( context ) );
            if( payloadConfigurator == null ) throw new ArgumentNullException( nameof( payloadConfigurator ) );
            var monitor = GetRequestMonitor( context.HttpContext );

            GetWFAData( context.HttpContext, context.Properties, out var fAuth, out var impersonateActualUser, out var initialScheme, out var callerOrigin, out var returnUrl, out var userData );

            string callingScheme = context.Scheme.Name;
            object payload = _loginService.CreatePayload( context.HttpContext, monitor, callingScheme );
            payloadConfigurator( (T)payload );

            // When Authentication Challenge has been called directly (LoginMode is WebFrontAuthLoginMode.None), we don't have
            // any scheme: we steal the context.RedirectUri as being the final redirect url.
            if( initialScheme == null )
            {
                returnUrl = context.ReturnUri;
            }
            var wfaSC = new WebFrontAuthLoginContext( context.HttpContext,
                                                      this,
                                                      _tokenService.TypeSystem,
                                                      initialScheme != null
                                                          ? WebFrontAuthLoginMode.StartLogin
                                                          : WebFrontAuthLoginMode.None,
                                                      callingScheme,
                                                      payload,
                                                      context.Properties,
                                                      initialScheme,
                                                      fAuth,
                                                      impersonateActualUser,
                                                      returnUrl,
                                                      callerOrigin,
                                                      userData );
            // We always handle the response (we skip the final standard SignIn process).
            context.HandleResponse();

            return UnifiedLoginAsync( monitor, wfaSC, actualLogin =>
            {
                return _loginService.LoginAsync( context.HttpContext, monitor, callingScheme, payload, actualLogin );
            } );
        }

        internal void ValidateCoreParameters( IActivityMonitor monitor,
                                              WebFrontAuthLoginMode mode,
                                              string? returnUrl, 
                                              string? callerOrigin, 
                                              IAuthenticationInfo current, 
                                              bool impersonateActualUser, 
                                              IErrorContext ctx )
        {
            if( mode == WebFrontAuthLoginMode.StartLogin )
            {
                // ReturnUrl (inline) and CallerOrigin (popup) cannot be both null or both not null.
                if( (returnUrl != null) == (callerOrigin != null) )
                {
                    ctx.SetError( "ReturnXOrCaller", "One and only one among returnUrl and callerOrigin must be specified." );
                    monitor.Error( WebFrontAuthMonitorTag, "One and only one among returnUrl and callerOrigin must be specified." );
                    return;
                }
            }
            if( !CheckLoginWhileImpersonation( monitor, current, impersonateActualUser, ctx ) )
            {
                return;
            }
            if( returnUrl != null
                && !_allowedReturnUrls.Any( p => returnUrl.StartsWith( p, StringComparison.Ordinal ) ) )
            {
                ctx.SetError( "DisallowedReturnUrl", $"The returnUrl='{returnUrl}' doesn't start with any of configured AllowedReturnUrls prefixes." );
                monitor.Error( WebFrontAuthMonitorTag, $"ReturnUrl '{returnUrl}' doesn't match: '{_allowedReturnUrls.Concatenate("', '")}'." );
                return;
            }
        }

        /// <summary>
        /// Login is always forbidden whenever the user is impersonated unless we must impersonate the actual user.
        /// </summary>
        static bool CheckLoginWhileImpersonation( IActivityMonitor monitor, IAuthenticationInfo current, bool impersonateActualUser, IErrorContext ctx )
        {
            if( current.IsImpersonated && !impersonateActualUser )
            {
                ctx.SetError( "LoginWhileImpersonation", "Login is not allowed while impersonation is active." );
                monitor.Error( WebFrontAuthMonitorTag, $"Login is not allowed while impersonation is active. UserId: {current.User.UserId}, ActualUserId: {current.ActualUser.UserId}." );
                return false;
            }
            return true;
        }

        internal async Task UnifiedLoginAsync( IActivityMonitor monitor, WebFrontAuthLoginContext ctx, Func<bool,Task<UserLoginResult>> logger )
        {
            // Double check of the core parameters.
            // If here the check fails, it means that the AuthenticationProperties have been tampered!
            // This is highly unlikely.
            ValidateCoreParameters( monitor, ctx.LoginMode, ctx.ReturnUrl, ctx.CallerOrigin, ctx.InitialAuthentication, ctx.ImpersonateActualUser, ctx );
            await DoUnifiedLoginAsync( monitor, ctx, logger );
            await ctx.SendResponseAsync( monitor );
        }

        async Task DoUnifiedLoginAsync( IActivityMonitor monitor, WebFrontAuthLoginContext ctx, Func<bool, Task<UserLoginResult>> logger )
        {
            UserLoginResult? u = null;
            if( !ctx.HasError )
            {
                // The logger function must kindly return an unlogged UserLoginResult if it cannot log the user in.
                u = await SafeCallLoginAsync( monitor, ctx, logger, actualLogin: _validateLoginService == null );
            }
            if( !ctx.HasError )
            {
                Debug.Assert( u != null );
                int currentlyLoggedIn = ctx.InitialAuthentication.User.UserId;
                if( !u.IsSuccess )
                {
                    // login failed.
                    // If the login failed because user is not registered: entering the account binding or auto registration features,
                    // but only if the login is not trying to impersonate the current actor.
                    if( ctx.ImpersonateActualUser )
                    {
                        ctx.SetError( u );
                        monitor.Error( WebFrontAuthMonitorTag, $"User.LoginError: Login with ImpersonateActualUser (current is {currentlyLoggedIn}) tried '{ctx.CallingScheme}' scheme and failed." );
                    }
                    else
                    {
                        if( u.IsUnregisteredUser )
                        {
                            if( currentlyLoggedIn != 0 )
                            {
                                bool raiseError = true;
                                // A user is currently logged in.
                                if( _autoBindingAccountService != null )
                                {
                                    UserLoginResult? uBound = await _autoBindingAccountService.BindAccountAsync( monitor, ctx );
                                    if( uBound != null )
                                    {
                                        raiseError = false;
                                        if( !uBound.IsSuccess ) ctx.SetError( uBound );
                                        else
                                        {
                                            if( u != uBound )
                                            {
                                                u = uBound;
                                                monitor.Info( WebFrontAuthMonitorTag, $"Account.AutoBinding: {currentlyLoggedIn} now bound to '{ctx.CallingScheme}' scheme." );
                                            }
                                        }
                                    }
                                }
                                if( raiseError )
                                {
                                    ctx.SetError( "Account.AutoBindingDisabled", "Automatic account binding is disabled." );
                                    monitor.Error( WebFrontAuthMonitorTag, $"Account.AutoBindingDisabled: {currentlyLoggedIn} tried '{ctx.CallingScheme}' scheme." );
                                }
                            }
                            else
                            {
                                bool raiseError = true;
                                if( _autoCreateAccountService != null )
                                {
                                    UserLoginResult? uAuto = await _autoCreateAccountService.CreateAccountAndLoginAsync( monitor, ctx );
                                    if( uAuto != null )
                                    {
                                        raiseError = false;
                                        if( !uAuto.IsSuccess ) ctx.SetError( uAuto );
                                        else u = uAuto;
                                    }
                                }
                                if( raiseError )
                                {
                                    ctx.SetError( "User.AutoRegistrationDisabled", "Automatic user registration is disabled." );
                                    monitor.Error( WebFrontAuthMonitorTag, $"User.AutoRegistrationDisabled: Automatic user registration is disabled (scheme: {ctx.CallingScheme})." );
                                }
                            }
                        }
                        else
                        {
                            ctx.SetError( u );
                            monitor.Trace( WebFrontAuthMonitorTag, $"User.LoginError: ({u.LoginFailureCode}) {u.LoginFailureReason}" );
                        }
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
                            u = await SafeCallLoginAsync( monitor, ctx, logger, actualLogin: true );
                        }
                    }
                }
                // Eventually...
                if( !ctx.HasError )
                {
                    Debug.Assert( u != null && u.UserInfo != null, "Login succeeds." );
                    if( currentlyLoggedIn != 0 && u.UserInfo.UserId != currentlyLoggedIn && !ctx.ImpersonateActualUser )
                    {
                        monitor.Warn( WebFrontAuthMonitorTag, $"Account.Relogin: User {currentlyLoggedIn} logged again as {u.UserInfo.UserId} via '{ctx.CallingScheme}' scheme without logout." );
                    }
                    ctx.SetSuccessfulLogin( u );
                    monitor.Info( WebFrontAuthMonitorTag, $"Logged in user {u.UserInfo.UserId} via '{ctx.CallingScheme}'." );
                }
            }
        }

        /// <summary>
        /// Calls the actual logger function (that must kindly return an unlogged UserLoginResult if it cannot log the user in)
        /// in a try/catch and sets an error on the context only if it throws.
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="ctx">The login context.</param>
        /// <param name="logger">The actual login function.</param>
        /// <param name="actualLogin">True for an actual login, false otherwise.</param>
        /// <returns>A login result (that may be unsuccessful).</returns>
        static async Task<UserLoginResult?> SafeCallLoginAsync( IActivityMonitor monitor, WebFrontAuthLoginContext ctx, Func<bool, Task<UserLoginResult>> logger,  bool actualLogin )
        {
            UserLoginResult? u = null;
            try
            {
                u = await logger( actualLogin );
                if( u == null )
                {
                    monitor.Fatal( WebFrontAuthMonitorTag, "Login service returned a null UserLoginResult." );
                    ctx.SetError( "InternalError", "Login service returned a null UserLoginResult." );
                }
            }
            catch( Exception ex )
            {
                monitor.Error( WebFrontAuthMonitorTag, "While calling login service.", ex );
                ctx.SetError( ex );
            }
            return u;
        }
    }
}

