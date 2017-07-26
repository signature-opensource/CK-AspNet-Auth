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
using Microsoft.AspNetCore.Http.Features.Authentication;
using Microsoft.Extensions.Primitives;
using CK.Core;

namespace CK.AspNet.Auth
{
    /// <summary>
    /// Handles both a cookie and a token authentication.
    /// This middleware must be added once and only once at the beginning of the pipeline.
    /// </summary>
    public sealed class WebFrontAuthMiddleware : AuthenticationMiddleware<WebFrontAuthMiddlewareOptions>
    {
        readonly static PathString _cSegmentPath = "/c";

        readonly WebFrontAuthService _authService;
        readonly IAuthenticationTypeSystem _typeSystem;
        readonly IWebFrontAuthLoginService _loginService;
        readonly PathString _entryPath;

        /// <summary>
        /// Initializes a new <see cref="WebFrontAuthMiddleware"/>.
        /// </summary>
        /// <param name="next">The next middleware.</param>
        /// <param name="dataProtectionProvider">The data protecion provider.</param>
        /// <param name="loggerFactory">The logger factory.</param>
        /// <param name="urlEncoder">The url encoder.</param>
        /// <param name="loginService">The login service.</param>
        /// <param name="authService">The authentication service.</param>
        /// <param name="loginService">The login service.</param>
        /// <param name="options">Middleware options.</param>
        public WebFrontAuthMiddleware(
                RequestDelegate next,
                IDataProtectionProvider dataProtectionProvider,
                ILoggerFactory loggerFactory,
                UrlEncoder urlEncoder,
                WebFrontAuthService authService,
                IAuthenticationTypeSystem typeSystem,
                IWebFrontAuthLoginService loginService,
                IOptions<WebFrontAuthMiddlewareOptions> options )
            : base( next, options, loggerFactory, urlEncoder )
        {
            if( dataProtectionProvider == null ) throw new ArgumentNullException( nameof( dataProtectionProvider ) );
            if( authService == null ) throw new ArgumentNullException( nameof( authService ) );
            if( Options.AuthenticationScheme != WebFrontAuthMiddlewareOptions.OnlyAuthenticationScheme )
            {
                throw new ArgumentException( $"Must not be changed.", nameof( Options.AuthenticationScheme ) );
            }
            _authService = authService;
            _typeSystem = typeSystem;
            _loginService = loginService;
            var provider = Options.DataProtectionProvider ?? dataProtectionProvider;
            IDataProtector dataProtector = provider.CreateProtector( typeof( WebFrontAuthMiddleware ).FullName );
            var cookieFormat = new AuthenticationInfoSecureDataFormat( _typeSystem, dataProtector.CreateProtector( "Cookie", "v1" ) );
            var tokenFormat = new AuthenticationInfoSecureDataFormat( _typeSystem, dataProtector.CreateProtector( "Token", "v1" ) );
            var extraDataFormat = new ExtraDataSecureDataFormat( dataProtector.CreateProtector( "Extra", "v1" ) );
            _authService.Initialize( dataProtector, cookieFormat, tokenFormat, extraDataFormat, Options );
            _entryPath = Options.EntryPath;
        }

        class Handler : AuthenticationHandler<WebFrontAuthMiddlewareOptions>
        {
            readonly WebFrontAuthMiddleware _middleware;
            readonly WebFrontAuthService _authService;
            readonly IAuthenticationTypeSystem _typeSystem;
            readonly IWebFrontAuthLoginService _loginService;

            public Handler( WebFrontAuthMiddleware middleware )
            {
                _middleware = middleware;
                _authService = middleware._authService;
                _typeSystem = middleware._typeSystem;
                _loginService = middleware._loginService;
            }

            public override Task<bool> HandleRequestAsync()
            {
                PathString remainder;
                if( Request.Path.StartsWithSegments( _middleware._entryPath, out remainder ) )
                {
                    Response.SetNoCacheAndDefaultStatus( StatusCodes.Status404NotFound );
                    if( remainder.StartsWithSegments( _cSegmentPath, StringComparison.Ordinal, out PathString cBased ) )
                    {
                        if( cBased.Value == "/refresh" )
                        {
                            return HandleRefresh();
                        }
                        else if( cBased.Value == "/basicLogin" )
                        {
                            if( _loginService.HasBasicLogin )
                            {
                                if( HttpMethods.IsPost( Request.Method ) ) return DirectBasicLogin();
                                Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
                            }
                        }
                        else if( cBased.Value == "/startLogin" )
                        {
                            return StartLogin();
                        }
                        else if( cBased.Value == "/endLogin" )
                        {
                            if( HttpMethods.IsPost( Request.Method ) ) return EndLogin( Context.GetRequestMonitor() );
                            Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
                        }
                        else if( cBased.Value == "/unsafeDirectLogin" )
                        {
                            if( HttpMethods.IsPost( Request.Method ) ) return UnsafeDirectLogin();
                            Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
                        }
                        else if( cBased.Value == "/logout" )
                        {
                            return HandleLogout();
                        }
                    }
                    else
                    {
                        if( remainder.Value == "/token" ) return HandleToken();
                    }
                    return Task.FromResult( true );
                }
                return base.HandleRequestAsync();
            }

            Task<bool> HandleRefresh()
            {
                IAuthenticationInfo authInfo = _authService.EnsureAuthenticationInfo( Context );
                Debug.Assert( authInfo != null );
                bool refreshable = false;
                if( authInfo.Level >= AuthLevel.Normal && Options.SlidingExpirationTime > TimeSpan.Zero )
                {
                    refreshable = true;
                    DateTime newExp = DateTime.UtcNow + Options.SlidingExpirationTime;
                    if( newExp > authInfo.Expires.Value )
                    {
                        authInfo = authInfo.SetExpires( newExp );
                    }
                }
                JObject response = CreateAuthResponse( authInfo, refreshable );
                if( Request.Query.Keys.Contains( "schemes" ) )
                {
                    IReadOnlyList<string> list = Options.AvailableSchemes;
                    if( list == null || list.Count == 0 ) list = _loginService.Providers;
                    response.Add( "schemes", new JArray( _loginService.Providers ) );
                }
                _authService.SetCookies( Context, authInfo );
                return WriteResponseAsync( response );
            }

            Task<bool> HandleToken()
            {
                var info = _authService.EnsureAuthenticationInfo( Context );
                var o = _typeSystem.AuthenticationInfo.ToJObject( info );
                return WriteResponseAsync( o );
            }

            Task<bool> HandleLogout()
            {
                _authService.Logout( Context );
                Context.Response.StatusCode = StatusCodes.Status200OK;
                return Task.FromResult( true );
            }

            async Task<bool> StartLogin()
            {
                string scheme = Request.Query["scheme"];
                if( scheme == null )
                {
                    Response.StatusCode = StatusCodes.Status400BadRequest;
                    return true;
                }
                string returnUrl = Request.Query["returnUrl"];

                IEnumerable<KeyValuePair<string, StringValues>> userData = null;
                if( returnUrl == null )
                {
                    if( HttpMethods.IsPost( Request.Method ) )
                    {
                        userData = Request.Form;
                    }
                    else
                    {
                        userData = Request.Query
                                           .Where( k => !string.Equals( k.Key, "scheme", StringComparison.OrdinalIgnoreCase )
                                                        && !string.Equals( k.Key, "returnUrl", StringComparison.OrdinalIgnoreCase ) );
                    }
                }
                var current = _authService.EnsureAuthenticationInfo( Context );

                AuthenticationProperties p = new AuthenticationProperties();
                p.Items.Add( "WFA-S", scheme );
                if( !current.IsNullOrNone() ) p.Items.Add( "WFA-C", _authService.ProtectAuthenticationInfo( Context, current ) );
                if( returnUrl != null ) p.Items.Add( "WFA-R", returnUrl );
                else if( userData.Any() ) p.Items.Add( "WFA-D", _authService.ProtectExtraData( Context, userData ) );
                await Context.Authentication.ChallengeAsync( scheme, p );
                return true;
            }

            async Task<bool> EndLogin( IActivityMonitor monitor )
            {
                Debug.Assert( HttpMethods.IsPost( Request.Method ) );
                string cData = Request.Form["s"];
                string retUrl = Request.Form["r"];
                if( !HttpMethods.IsPost( Request.Method ) 
                    || string.IsNullOrWhiteSpace(cData)
                    || retUrl == null )
                {

                    monitor.Fatal( "Illegal call to EndLogin." );
                    Response.StatusCode = StatusCodes.Status400BadRequest;
                }
                try
                {
                    string data = _authService.UnprotectString( Context, cData );
                    JObject o = JObject.Parse( data );
                    IUserInfo u = _typeSystem.UserInfo.FromJObject( (JObject)o["u"] );
                    LoginResult r = HandleLogin( u );
                    if( !string.IsNullOrEmpty( retUrl ) )
                    {
                        var caller = new Uri( $"{Context.Request.Scheme}://{Context.Request.Host}/" );
                        var target = new Uri( caller, retUrl );
                        Response.StatusCode = StatusCodes.Status200OK;
                        Response.ContentType = "text/html";
                        var t = $@"<!DOCTYPE html><html><body><script>(function(){{window.url='{target}';}})();</script></body></html>";
                        await Response.WriteAsync( t );
                    }
                    else
                    {
                        o.Remove( "u" );
                        r.Response.Merge( o );
                        await Context.Response.WritePostMessageAsync( r.Response );
                    }
                }
                catch( Exception ex )
                {
                    if( string.IsNullOrEmpty( retUrl ) )
                    {
                        await Context.Response.WritePostMessageWithErrorAsync( ex );
                    }
                    else
                    {
                        Context.Response.RedirectToReturnUrlWithError( ex );
                    }
                }
                return true;
            }

            #region Unsafe Direct Login
            class ProviderLoginRequest
            {
                public string Scheme { get; set; }
                public object Payload { get; set; }
            }

            async Task<bool> UnsafeDirectLogin()
            {
                Response.StatusCode = StatusCodes.Status403Forbidden;
                if( Options.UnsafeDirectLoginAllower != null )
                {
                    ProviderLoginRequest req = await ReadProviderLoginRequest();
                    if( req != null && Options.UnsafeDirectLoginAllower( Context, req.Scheme ) )
                    {
                        IUserInfo u = await _loginService.LoginAsync( Context, req.Scheme, req.Payload );
                        await DoDirectLogin( u );
                    }
                }
                return true;
            }

            async Task<ProviderLoginRequest> ReadProviderLoginRequest()
            {
                ProviderLoginRequest req = null;
                try
                {
                    var b = await new StreamReader( Request.Body ).ReadToEndAsync();
                    // By using our poor StringMatcher here, we parse the JSON
                    // to basic List<KeyValuePair<string, object>> because 
                    // JObject are IEnumerable<KeyValuePair<string, JToken>> and
                    // KeyValuePair is not covariant. Moreover JToken is not easily 
                    // convertible (to basic types) without using the JToken type.
                    // A dependency on NewtonSoft.Json may not be suitable for some 
                    // providers.
                    var m = new StringMatcher( b );
                    if( m.MatchJSONObject( out object val ) )
                    {
                        var o = val as List<KeyValuePair<string, object>>;
                        if( o != null )
                        {
                            string provider = o.FirstOrDefault( kv => StringComparer.OrdinalIgnoreCase.Equals( kv.Key, "provider" ) ).Value as string;
                            if( !string.IsNullOrWhiteSpace( provider ) )
                            {
                                req = new ProviderLoginRequest()
                                {
                                    Scheme = provider,
                                    Payload = o.FirstOrDefault( kv => StringComparer.OrdinalIgnoreCase.Equals( kv.Key, "payload" ) ).Value
                                };
                            }
                        }
                    }
                }
                catch( Exception ex )
                {
                    Options.OnError?.Invoke( Context, ex );
                }
                if( req == null ) Response.StatusCode = StatusCodes.Status400BadRequest;
                return req;
            }
            #endregion

            #region Basic Authentication support

            class BasicLoginRequest
            {
                public string UserName { get; set; }
                public string Password { get; set; }
            }

            async Task<bool> DirectBasicLogin()
            {
                Debug.Assert( _loginService.HasBasicLogin );
                BasicLoginRequest req = await ReadBasicLoginRequest();
                if( req != null )
                {
                    IUserInfo u = await _loginService.BasicLoginAsync( Context, req.UserName, req.Password );
                    await DoDirectLogin( u );
                }
                return true;
            }

            async Task<BasicLoginRequest> ReadBasicLoginRequest()
            {
                BasicLoginRequest req = null;
                try
                {
                    var b = await new StreamReader( Request.Body ).ReadToEndAsync();
                    var r = JsonConvert.DeserializeObject<BasicLoginRequest>( b );
                    if( !string.IsNullOrWhiteSpace( r.UserName ) && !string.IsNullOrWhiteSpace( r.Password ) ) req = r;
                }
                catch( Exception ex )
                {
                    Options.OnError?.Invoke( Context, ex );
                }
                if( req == null ) Response.StatusCode = StatusCodes.Status400BadRequest;
                return req;
            }

            #endregion

            #region Authentication handling (handles standard Authenticate API).
            protected override Task<AuthenticateResult> HandleAuthenticateAsync()
            {
                IAuthenticationInfo authInfo = _authService.EnsureAuthenticationInfo( Context );
                if( authInfo.IsNullOrNone() ) return Task.FromResult( AuthenticateResult.Skip() );
                var principal = new ClaimsPrincipal();
                principal.AddIdentity( _typeSystem.AuthenticationInfo.ToClaimsIdentity( authInfo, userInfoOnly: false ) );
                var ticket = new AuthenticationTicket( principal, new AuthenticationProperties(), Options.AuthenticationScheme );
                return Task.FromResult( AuthenticateResult.Success( ticket ) );
            }

            #endregion

            struct LoginResult
            {
                /// <summary>
                /// Standard JSON response.
                /// It is mutable: properties can be appended.
                /// </summary>
                public readonly JObject Response;
                
                /// <summary>
                /// Info can be null.
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
            /// <param name="u">The user info to login.</param>
            /// <returns>A login result with the JSON response and authentication info.</returns>
            LoginResult HandleLogin( IUserInfo u )
            {
                IAuthenticationInfo authInfo = u != null && u.UserId != 0
                                                ? _typeSystem.AuthenticationInfo.Create( u, DateTime.UtcNow + Options.ExpireTimeSpan )
                                                : null;
                JObject response = CreateAuthResponse( authInfo, authInfo != null && Options.SlidingExpirationTime > TimeSpan.Zero );
                _authService.SetCookies( Context, authInfo );
                return new LoginResult( response, authInfo );
            }

            /// <summary>
            /// Calls <see cref="HandleLogin"/> and writes the JSON response.
            /// </summary>
            /// <param name="u">The user info to login.</param>
            /// <returns>Always true.</returns>
            Task<bool> DoDirectLogin( IUserInfo u )
            {
                LoginResult r = HandleLogin( u );
                return WriteResponseAsync( r.Response, r.Info == null ? StatusCodes.Status401Unauthorized : StatusCodes.Status200OK );
            }

            JObject CreateAuthResponse( IAuthenticationInfo authInfo, bool refreshable )
            {
                return new JObject(
                    new JProperty( "info", _typeSystem.AuthenticationInfo.ToJObject( authInfo ) ),
                    new JProperty( "token", _authService.CreateToken( Context, authInfo ) ),
                    new JProperty( "refreshable", refreshable ) );
            }

            async Task<bool> WriteResponseAsync( JObject o, int code = StatusCodes.Status200OK )
            {
                await Response.WriteAsync( o, code );
                return true;
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
