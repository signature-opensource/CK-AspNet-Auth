using CK.Auth;
using CK.Core;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Http.Features.Authentication;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading.Tasks;

namespace CK.AspNet.Auth
{
    /// <summary>
    /// Default implementation of an authentication service.
    /// </summary>
    public class WebFrontAuthService
    {
        /// <summary>
        /// Name of the authentication cookie.
        /// </summary>
        public const string AuthCookieName = ".webFront";

        /// <summary>
        /// Name of the long term authentication cookie.
        /// </summary>
        public const string UnsafeCookieName = ".webFrontLT";

        readonly IAuthenticationTypeSystem _typeSystem;
        readonly IWebFrontAuthLoginService _loginService;

        IDataProtector _genericProtector;
        AuthenticationInfoSecureDataFormat _tokenFormat;
        AuthenticationInfoSecureDataFormat _cookieFormat;
        ExtraDataSecureDataFormat _extraDataFormat;
        WebFrontAuthMiddlewareOptions _options;
        string _cookiePath;
        TimeSpan _halfSlidingExpirationTime;

        /// <summary>
        /// Initializes a new <see cref="WebFrontAuthService"/>.
        /// </summary>
        /// <param name="typeSystem">A <see cref="IAuthenticationTypeSystem"/>.</param>
        /// <param name="loginService">Login service.</param>
        public WebFrontAuthService( IAuthenticationTypeSystem typeSystem, IWebFrontAuthLoginService loginService )
        {
            _typeSystem = typeSystem;
            _loginService = loginService;
        }

        /// <summary>
        /// This is called by the WebFrontAuthMiddleware constructor.
        /// </summary>
        /// <param name="genericProtector">Base protector.</param>
        /// <param name="cookieFormat">The formatter for cookies.</param>
        /// <param name="tokenFormat">The formatter for tokens.</param>
        /// <param name="extraDataFormat">The formatter for extra data.</param>
        /// <param name="options">The middleware options.</param>
        internal void Initialize(
            IDataProtector genericProtector,
            AuthenticationInfoSecureDataFormat cookieFormat,
            AuthenticationInfoSecureDataFormat tokenFormat,
            ExtraDataSecureDataFormat extraDataFormat,
            WebFrontAuthMiddlewareOptions options )
        {
            if( _tokenFormat != null ) throw new InvalidOperationException( "Only one WebFrontAuthMiddleware must be used." );
            Debug.Assert( genericProtector != null );
            Debug.Assert( cookieFormat != null );
            Debug.Assert( tokenFormat != null );
            Debug.Assert( options != null );
            _genericProtector = genericProtector;
            _cookieFormat = cookieFormat;
            _tokenFormat = tokenFormat;
            _extraDataFormat = extraDataFormat;
            _options = options;
            _cookiePath = options.EntryPath + "/c/";
            _halfSlidingExpirationTime = new TimeSpan( options.SlidingExpirationTime.Ticks / 2 );
        }

        internal string ProtectAuthenticationInfo( HttpContext c, IAuthenticationInfo info )
        {
            Debug.Assert( info != null );
            return _tokenFormat.Protect( info, GetTlsTokenBinding( c ) );
        }

        internal IAuthenticationInfo UnprotectAuthenticationInfo( HttpContext c, string data )
        {
            Debug.Assert( data != null );
            return _tokenFormat.Unprotect( data, GetTlsTokenBinding( c ) );
        }

        internal string ProtectExtraData( HttpContext c, IEnumerable<KeyValuePair<string, StringValues>> info )
        {
            Debug.Assert( info != null );
            return _extraDataFormat.Protect( info, GetTlsTokenBinding( c ) );
        }

        internal IEnumerable<KeyValuePair<string, StringValues>> UnprotectExtraData( HttpContext c, string data )
        {
            Debug.Assert( data != null );
            return _extraDataFormat.Unprotect( data, GetTlsTokenBinding( c ) );
        }

        internal string ProtectString( HttpContext c, string data, TimeSpan duration )
        {
            Debug.Assert( data != null );
            return _genericProtector
                        .CreateProtector( GetTlsTokenBinding( c ) ?? "" )
                        .ToTimeLimitedDataProtector()
                        .Protect( data, duration );
        }

        internal string UnprotectString( HttpContext c, string data )
        {
            Debug.Assert( data != null );
            return _genericProtector
                        .CreateProtector( GetTlsTokenBinding( c ) ?? "" )
                        .ToTimeLimitedDataProtector()
                        .Unprotect( data );
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
            if( c.Items.TryGetValue( typeof( IAuthenticationInfo ), out o ) )
            {
                authInfo = (IAuthenticationInfo)o;
            }
            else
            {
                authInfo = ReadAndCacheAuthenticationHeader( c );
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
        internal IAuthenticationInfo ReadAndCacheAuthenticationHeader( HttpContext c )
        {
            Debug.Assert( !c.Items.ContainsKey( typeof( IAuthenticationInfo ) ) );
            var monitor = c.GetRequestMonitor();
            IAuthenticationInfo authInfo = null;
            try
            {
                // First try from the bearer: this is always the preferred way.
                string authorization = c.Request.Headers[_options.BearerHeaderName];
                if( !string.IsNullOrEmpty( authorization )
                    && authorization.StartsWith( "Bearer ", StringComparison.OrdinalIgnoreCase ) )
                {
                    Debug.Assert( "Bearer ".Length == 7 );
                    string token = authorization.Substring( 7 ).Trim();
                    authInfo = _tokenFormat.Unprotect( token, GetTlsTokenBinding( c ) );
                }
                else
                {
                    // Best case is when we have the authentication cookie, otherwise use the long term cookie.
                    string cookie;
                    if( Options.CookieMode != AuthenticationCookieMode.None && c.Request.Cookies.TryGetValue( AuthCookieName, out cookie ) )
                    {
                        authInfo = _cookieFormat.Unprotect( cookie, GetTlsTokenBinding( c ) );
                    }
                    else if( Options.UseLongTermCookie && c.Request.Cookies.TryGetValue( UnsafeCookieName, out cookie ) )
                    {
                        IUserInfo info = _typeSystem.UserInfo.FromJObject( JObject.Parse( cookie ) );
                        authInfo = _typeSystem.AuthenticationInfo.Create( info );
                    }
                }
                if( authInfo == null ) authInfo = _typeSystem.AuthenticationInfo.None;
                // Upon each authentication, when rooted Cookies are used and the SlidingExpiration is on, handles it.
                if( authInfo.Level >= AuthLevel.Normal
                    && Options.CookieMode == AuthenticationCookieMode.RootPath
                    && _halfSlidingExpirationTime > TimeSpan.Zero
                    && authInfo.Expires.Value <= DateTime.UtcNow + _halfSlidingExpirationTime )
                {
                    var authInfo2 = authInfo.SetExpires( DateTime.UtcNow + Options.SlidingExpirationTime );
                    SetCookies( c, authInfo = authInfo2 );
                }
            }
            catch( Exception ex )
            {
                monitor.Error( ex );
                authInfo = _typeSystem.AuthenticationInfo.None;
            }
            c.Items.Add( typeof( IAuthenticationInfo ), authInfo );
            return authInfo;
        }

        #region Cookie management

        internal void Logout( HttpContext ctx )
        {
            ClearCookie( ctx, AuthCookieName );
            if( ctx.Request.Query.ContainsKey( "full" ) ) ClearCookie( ctx, UnsafeCookieName );
        }

        internal void SetCookies( HttpContext ctx, IAuthenticationInfo authInfo )
        {
            if( authInfo != null && Options.UseLongTermCookie && authInfo.UnsafeActualUser.UserId != 0 )
            {
                string value = _typeSystem.UserInfo.ToJObject( authInfo.UnsafeActualUser ).ToString( Formatting.None );
                ctx.Response.Cookies.Append( UnsafeCookieName, value, CreateUnsafeCookieOptions( DateTime.UtcNow + Options.UnsafeExpireTimeSpan ) );
            }
            else ClearCookie( ctx, UnsafeCookieName );
            if( authInfo != null && Options.CookieMode != AuthenticationCookieMode.None && authInfo.Level >= AuthLevel.Normal )
            {
                Debug.Assert( authInfo.Expires.HasValue );
                string value = _cookieFormat.Protect( authInfo, WebFrontAuthService.GetTlsTokenBinding( ctx ) );
                ctx.Response.Cookies.Append( AuthCookieName, value, CreateAuthCookieOptions( ctx, authInfo.Expires ) );
            }
            else ClearCookie( ctx, AuthCookieName );
        }

        CookieOptions CreateAuthCookieOptions( HttpContext ctx, DateTimeOffset? expires = null )
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

        CookieOptions CreateUnsafeCookieOptions( DateTimeOffset? expires = null )
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

        void ClearCookie( HttpContext ctx, string cookieName )
        {
            ctx.Response.Cookies.Delete( cookieName, cookieName == AuthCookieName
                                                ? CreateAuthCookieOptions( ctx )
                                                : CreateUnsafeCookieOptions() );
        }

        #endregion

        /// <summary>
        /// Returns the token (null if authInfo is null or none).
        /// </summary>
        /// <param name="c">The context.</param>
        /// <param name="authInfo">The authentication info. Can be null.</param>
        /// <returns>The token (can be null).</returns>
        internal string CreateToken( HttpContext c, IAuthenticationInfo authInfo )
        {
            return authInfo.IsNullOrNone() ? null : _tokenFormat.Protect( authInfo, GetTlsTokenBinding( c ) );
        }

        static string GetTlsTokenBinding( HttpContext c )
        {
            var binding = c.Features.Get<ITlsTokenBindingFeature>()?.GetProvidedTokenBindingId();
            return binding == null ? null : Convert.ToBase64String( binding );
        }

        /// <summary>
        /// Gets the middleware options.
        /// </summary>
        protected WebFrontAuthMiddlewareOptions Options => _options;

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
        public async Task HandleRemoteAuthentication<T>( TicketReceivedContext context, Action<T> payloadConfigurator )
        {
            if( context == null ) throw new ArgumentNullException( nameof( context ) );
            if( payloadConfigurator == null ) throw new ArgumentNullException( nameof( payloadConfigurator ) );
            var monitor = context.HttpContext.GetRequestMonitor();
            string initialScheme, c, d, r;
            context.Properties.Items.TryGetValue( "WFA-S", out initialScheme );
            context.Properties.Items.TryGetValue( "WFA-C", out c );
            context.Properties.Items.TryGetValue( "WFA-D", out d );
            context.Properties.Items.TryGetValue( "WFA-R", out r );

            IAuthenticationInfo initialAuth = c == null
                                        ? _typeSystem.AuthenticationInfo.None
                                        : UnprotectAuthenticationInfo( context.HttpContext, c );
            List<KeyValuePair<string, StringValues>> userData = d == null
                                                                ? new List<KeyValuePair<string, StringValues>>()
                                                                : (List<KeyValuePair<string, StringValues>>)UnprotectExtraData( context.HttpContext, d );
            var wfaSC = new WebFrontAuthLoginContext(
                                context.HttpContext,
                                this,
                                _typeSystem,
                                context.Options.AuthenticationScheme,
                                context.Properties,
                                context.Principal,
                                initialScheme,
                                initialAuth,
                                r,
                                userData );
            // We always handle the response (we skip the final standard SignIn process).
            context.HandleResponse();

            if( wfaSC.InitialAuthentication.IsImpersonated )
            {
                wfaSC.SetError( "LoginWhileImpersonation", "Login is not allowed while impersonation is active." );
            }
            else
            {
                object payload = _loginService.CreatePayload( context.HttpContext, monitor, wfaSC.CallingScheme );
                payloadConfigurator( (T)payload );
                IUserInfo u = await _loginService.LoginAsync( context.HttpContext, monitor, wfaSC.CallingScheme, payload );
                int currentlyLoggedIn = wfaSC.InitialAuthentication.User.UserId;
                if( u == null || u.UserId == 0 )
                {
                    if( currentlyLoggedIn != 0 )
                    {
                        wfaSC.SetError( "Account.NoAutoBinding", "Automatic account binding is disabled." );
                    }
                    else
                    {
                        wfaSC.SetError( "User.NoAutoRegistration", "Automatic user registration is disabled." );
                    }
                }
                else
                {
                    if( currentlyLoggedIn != 0 && u.UserId != currentlyLoggedIn )
                    {
                        wfaSC.SetError( "Account.Conflict", "Conflicting existing login association." );
                    }
                    else
                    {
                        wfaSC.SetSuccessfulLogin( u );
                    }
                }
            }
            await wfaSC.SendResponse();
        }
    }

}
