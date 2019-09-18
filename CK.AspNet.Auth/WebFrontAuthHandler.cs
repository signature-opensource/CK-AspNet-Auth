using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Text.Encodings.Web;
using System.Diagnostics;
using Newtonsoft.Json.Linq;
using CK.Auth;
using Microsoft.AspNetCore.Http;
using CK.Core;
using System.Linq;
using Microsoft.Extensions.Primitives;
using System.Security.Claims;
using CK.Text;
using Newtonsoft.Json;
using Microsoft.AspNetCore.Authentication;
using System.Globalization;
using Microsoft.Extensions.DependencyInjection;

namespace CK.AspNet.Auth
{
    sealed class WebFrontAuthHandler : AuthenticationHandler<WebFrontAuthOptions>, IAuthenticationRequestHandler
    {
        readonly static PathString _cSegmentPath = "/c";

        readonly WebFrontAuthService _authService;
        readonly IAuthenticationTypeSystem _typeSystem;
        readonly IWebFrontAuthLoginService _loginService;
        readonly IWebFrontAuthImpersonationService _impersonationService;
        readonly IWebFrontAuthUnsafeDirectLoginAllowService _unsafeDirectLoginAllower;

        public WebFrontAuthHandler(
            IOptionsMonitor<WebFrontAuthOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            WebFrontAuthService authService,
            IAuthenticationTypeSystem typeSystem,
            IWebFrontAuthLoginService loginService,
            IWebFrontAuthImpersonationService impersonationService = null,
            IWebFrontAuthUnsafeDirectLoginAllowService unsafeDirectLoginAllower = null
            ) : base( options, logger, encoder, clock )
        {
            _authService = authService;
            _typeSystem = typeSystem;
            _loginService = loginService;
            _impersonationService = impersonationService;
            _unsafeDirectLoginAllower = unsafeDirectLoginAllower;
        }

        IActivityMonitor GetRequestMonitor( HttpContext c ) => c.RequestServices.GetService<IActivityMonitor>();

        public Task<bool> HandleRequestAsync()
        {
            PathString remainder;
            if( Request.Path.StartsWithSegments( Options.EntryPath, out remainder ) )
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
                            if( HttpMethods.IsPost( Request.Method ) ) return DirectBasicLogin( GetRequestMonitor( Context ) );
                            Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
                        }
                    }
                    else if( cBased.Value == "/startLogin" )
                    {
                        return HandleStartLogin( GetRequestMonitor( Context ) );
                    }
                    else if( cBased.Value == "/unsafeDirectLogin" )
                    {
                        if( HttpMethods.IsPost( Request.Method ) ) return HandleUnsafeDirectLogin( GetRequestMonitor( Context ) );
                        Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
                    }
                    else if( cBased.Value == "/logout" )
                    {
                        return HandleLogout();
                    }
                    else if( cBased.Value == "/impersonate" )
                    {
                        if( _impersonationService != null )
                        {
                            if( HttpMethods.IsPost( Request.Method ) ) return HandleImpersonate( GetRequestMonitor( Context ) );
                            Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
                        }
                    }
                }
                else
                {
                    if( remainder.Value == "/token" ) return HandleToken();
                }
                return Task.FromResult( true );
            }
            return Task.FromResult( false );
        }

        async Task<bool> HandleRefresh()
        {
            IAuthenticationInfo authInfo = _authService.EnsureAuthenticationInfo( Context );
            Debug.Assert( authInfo != null );
            if( Request.Query.Keys.Contains( "full" ) )
            {
                var newExpires = DateTime.UtcNow + _authService.CurrentOptions.ExpireTimeSpan;
                authInfo = await _loginService.RefreshAuthenticationInfoAsync( Context, GetRequestMonitor( Context ), authInfo, newExpires );
            }
            JObject response = GetRefreshResponseAndSetCookies( authInfo, Request.Query.Keys.Contains( "schemes" ) );
            return await WriteResponseAsync( response );
        }

        JObject GetRefreshResponseAndSetCookies( IAuthenticationInfo authInfo, bool addSchemes )
        {
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
            JObject response = _authService.CreateAuthResponse( Context, authInfo, refreshable );
            if( addSchemes )
            {
                IReadOnlyList<string> list = Options.AvailableSchemes;
                if( list == null || list.Count == 0 ) list = _loginService.Providers;
                response.Add( "schemes", new JArray( _loginService.Providers ) );
            }
            _authService.SetCookies( Context, authInfo );
            return response;
        }

        async Task<bool> HandleLogout()
        {
            _authService.Logout( Context );
            await Context.Response.WriteAsync( null, StatusCodes.Status200OK );
            return true;
        }

        async Task<bool> HandleStartLogin( IActivityMonitor monitor )
        {
            string scheme = Request.Query["scheme"];
            if( scheme == null )
            {
                Response.StatusCode = StatusCodes.Status400BadRequest;
                return true;
            }
            string returnUrl = Request.Query["returnUrl"];
            string callerOrigin = Request.Query["callerOrigin"];

            IEnumerable<KeyValuePair<string, StringValues>> userData;
            if( HttpMethods.IsPost( Request.Method ) )
            {
                if( callerOrigin == null ) callerOrigin = Request.Form["callerOrigin"];
                userData = Request.Form;
            }
            else userData = Request.Query;
            userData = userData.Where( k => !string.Equals( k.Key, "scheme", StringComparison.OrdinalIgnoreCase )
                                            && !string.Equals( k.Key, "returnUrl", StringComparison.OrdinalIgnoreCase )
                                            && !string.Equals( k.Key, "callerOrigin", StringComparison.OrdinalIgnoreCase ) );
            var current = _authService.EnsureAuthenticationInfo( Context );
            Debug.Assert( current != null );
            var startContext = new WebFrontAuthStartLoginContext( Context, _authService, scheme, current, userData, returnUrl, callerOrigin );
            // We test impersonation here: login is forbidden whenever the user is impersonated.
            // This check will also be done by WebFrontAuthService.UnifiedLogin.
            if( current.IsImpersonated )
            {
                startContext.SetError( "LoginWhileImpersonation", "Login is not allowed while impersonation is active." );
                monitor.Error( $"Login is not allowed while impersonation is active: {current.ActualUser.UserId} impersonated into {current.User.UserId}.", WebFrontAuthService.WebFrontAuthMonitorTag );
            }
            else
            {
                await _authService.OnHandlerStartLogin( monitor, startContext );
            }
            if( startContext.HasError )
            {
                await startContext.SendError();
            }
            else
            {
                AuthenticationProperties p = new AuthenticationProperties();
                p.Items.Add( "WFA-S", startContext.Scheme );
                if( !String.IsNullOrWhiteSpace( startContext.CallerOrigin ) ) p.Items.Add( "WFA-O", startContext.CallerOrigin );
                if( current.Level != AuthLevel.None ) p.Items.Add( "WFA-C", _authService.ProtectAuthenticationInfo( Context, current ) );
                if( startContext.ReturnUrl != null ) p.Items.Add( "WFA-R", startContext.ReturnUrl );
                else if( startContext.UserData.Count != 0 ) p.Items.Add( "WFA-D", _authService.ProtectExtraData( Context, startContext.UserData ) );
                if( startContext.DynamicScopes != null )
                {
                    p.Parameters.Add( "scope", startContext.DynamicScopes );
                }
                await Context.ChallengeAsync( scheme, p );
            }
            return true;
        }

        #region Unsafe Direct Login
        class ProviderLoginRequest
        {
            public string Scheme { get; set; }
            public object Payload { get; set; }
            public Dictionary<string, StringValues> UserData { get; } = new Dictionary<string, StringValues>();
        }

        async Task<bool> HandleUnsafeDirectLogin( IActivityMonitor monitor )
        {
            Response.StatusCode = StatusCodes.Status403Forbidden;
            if( _unsafeDirectLoginAllower != null )
            {
                ProviderLoginRequest req = ReadDirectLoginRequest( monitor );
                if( req != null && await _unsafeDirectLoginAllower.AllowAsync( Context, monitor, req.Scheme, req.Payload ) )
                {
                    // The req.Payload my be null here. We map it to an empty object to preserve the invariant of the context.
                    var payload = req.Payload ?? new Object();
                    var wfaSC = new WebFrontAuthLoginContext(
                                        Context,
                                        _authService,
                                        _typeSystem,
                                        WebFrontAuthLoginMode.UnsafeDirectLogin,
                                        req.Scheme,
                                        payload,
                                        null,
                                        req.Scheme,
                                        _authService.EnsureAuthenticationInfo( Context ),
                                        null,
                                        null,
                                        req.UserData.ToList()
                                        );

                    await _authService.UnifiedLogin( monitor, wfaSC, actualLogin =>
                    {
                        return _loginService.LoginAsync( Context, monitor, req.Scheme, payload, actualLogin );
                    } );
                }
            }
            return true;
        }

        ProviderLoginRequest ReadDirectLoginRequest( IActivityMonitor monitor )
        {
            ProviderLoginRequest req = null;
            try
            {
                string b;
                if( !Request.TryReadSmallBodyAsString( out b, 4096 ) ) return null;
                // By using our poor StringMatcher here, we parse the JSON
                // to basic List<KeyValuePair<string, object>> because 
                // JObject are IEnumerable<KeyValuePair<string, JToken>> and
                // KeyValuePair is not covariant. Moreover JToken is not easily 
                // convertible (to basic types) without using the JToken type.
                // A dependency on NewtonSoft.Json may not be suitable for some 
                // providers.
                var m = new StringMatcher( b );
                if( m.MatchJSONObject( out object val )
                    && val is List<KeyValuePair<string, object>> o )
                {
                    string provider = o.FirstOrDefault( kv => StringComparer.OrdinalIgnoreCase.Equals( kv.Key, "provider" ) ).Value as string;
                    if( !string.IsNullOrWhiteSpace( provider ) )
                    {
                        req = new ProviderLoginRequest()
                        {
                            Scheme = provider,
                            Payload = o.FirstOrDefault( kv => StringComparer.OrdinalIgnoreCase.Equals( kv.Key, "payload" ) ).Value
                        };
                        var userData = o.FirstOrDefault( kv => StringComparer.OrdinalIgnoreCase.Equals( kv.Key, "userData" ) ).Value;
                        if( userData is List<KeyValuePair<string, object>> data )
                        {
                            foreach( var kv in data )
                            {
                                req.UserData.Add( kv.Key, (string)kv.Value );
                            }
                        }
                    }
                }
            }
            catch( Exception ex )
            {
                monitor.Error( "Invalid payload.", ex, WebFrontAuthService.WebFrontAuthMonitorTag );
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
            public Dictionary<string, StringValues> UserData { get; } = new Dictionary<string, StringValues>();
        }

        async Task<bool> DirectBasicLogin( IActivityMonitor monitor )
        {
            Debug.Assert( _loginService.HasBasicLogin );
            BasicLoginRequest req = ReadBasicLoginRequest( monitor );
            if( req != null )
            {
                var wfaSC = new WebFrontAuthLoginContext(
                    Context,
                    _authService,
                    _typeSystem,
                    WebFrontAuthLoginMode.BasicLogin,
                    "Basic",
                    Tuple.Create( req.UserName, req.Password ),
                    null,
                    "Basic",
                    _authService.EnsureAuthenticationInfo( Context ),
                    null,
                    null,
                    req.UserData.ToList()
                    );

                await _authService.UnifiedLogin( monitor, wfaSC, actualLogin =>
                {
                    return _loginService.BasicLoginAsync( Context, monitor, req.UserName, req.Password, actualLogin );
                } );
            }
            return true;
        }

        BasicLoginRequest ReadBasicLoginRequest( IActivityMonitor monitor )
        {
            BasicLoginRequest req = null;
            try
            {
                string b;
                if( !Request.TryReadSmallBodyAsString( out b, 2048 ) ) return null;
                var r = JsonConvert.DeserializeObject<BasicLoginRequest>( b );
                if( !string.IsNullOrWhiteSpace( r.UserName ) && !string.IsNullOrWhiteSpace( r.Password ) ) req = r;
            }
            catch( Exception ex )
            {
                monitor.Error( ex );
            }
            if( req == null ) Response.StatusCode = StatusCodes.Status400BadRequest;
            return req;
        }

        #endregion

        #region Impersonation
        async Task<bool> HandleImpersonate( IActivityMonitor monitor )
        {
            Debug.Assert( _impersonationService != null && HttpMethods.IsPost( Request.Method ) );
            Response.StatusCode = StatusCodes.Status403Forbidden;
            IAuthenticationInfo info = _authService.EnsureAuthenticationInfo( Context );
            if( info.ActualUser.UserId != 0 )
            {
                int userId = -1;
                string userName = null;
                if( TryReadUserKey( monitor, ref userId, ref userName ) )
                {
                    if( userName == info.ActualUser.UserName || userId == info.ActualUser.UserId )
                    {
                        info = info.ClearImpersonation();
                        Response.StatusCode = StatusCodes.Status200OK;
                    }
                    else
                    {
                        IUserInfo target = userName != null
                                            ? await _impersonationService.ImpersonateAsync( Context, monitor, info, userName )
                                            : await _impersonationService.ImpersonateAsync( Context, monitor, info, userId );
                        if( target != null )
                        {
                            info = info.Impersonate( target );
                            Response.StatusCode = StatusCodes.Status200OK;
                        }
                    }
                    if( Response.StatusCode == StatusCodes.Status200OK )
                    {
                        await Response.WriteAsync( GetRefreshResponseAndSetCookies( info, addSchemes: false ) );
                    }
                }
            }
            return true;
        }

        bool TryReadUserKey( IActivityMonitor monitor, ref int userId, ref string userName )
        {
            string b;
            if( Request.TryReadSmallBodyAsString( out b, 512 ) )
            {
                var m = new StringMatcher( b );
                List<KeyValuePair<string, object>> param;
                if( m.MatchJSONObject( out object val )
                    && (param = val as List<KeyValuePair<string, object>>) != null
                    && param.Count == 1 )
                {
                    if( param[0].Key == "userName" )
                    {
                        if( param[0].Value is string n )
                        {
                            userName = n;
                            return true;
                        }
                    }
                    if( param[0].Key == "userId" )
                    {
                        if( param[0].Value is string n )
                        {
                            if( Int32.TryParse( n, NumberStyles.Integer, CultureInfo.InvariantCulture, out userId ) )
                            {
                                return true;
                            }
                        }
                        else if( param[0].Value is double d )
                        {
                            userId = (int)d;
                            return true;
                        }
                    }
                }
                Response.StatusCode = StatusCodes.Status400BadRequest;
            }
            Debug.Assert( Response.StatusCode == StatusCodes.Status400BadRequest );
            return false;
        }

        #endregion

        #region Authentication handling (handles standard Authenticate API).

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            IAuthenticationInfo authInfo = _authService.EnsureAuthenticationInfo( Context );
            if( authInfo.IsNullOrNone() )
            {
                return Task.FromResult( AuthenticateResult.Fail( "No current Authentication." ) );
            }
            
            var principal = new ClaimsPrincipal();
            principal.AddIdentity( _typeSystem.AuthenticationInfo.ToClaimsIdentity( authInfo, userInfoOnly: !Options.UseFullClaimsPrincipalOnAuthenticate ) );
            var ticket = new AuthenticationTicket( principal, new AuthenticationProperties(), Scheme.Name );
            return Task.FromResult( AuthenticateResult.Success( ticket ) );
        }

        #endregion

        Task<bool> HandleToken()
        {
            var info = _authService.EnsureAuthenticationInfo( Context );
            var o = _typeSystem.AuthenticationInfo.ToJObject( info );
            return WriteResponseAsync( o );
        }

        /// <summary>
        /// Writes the JObject and always returns true.
        /// </summary>
        /// <param name="o">The object.</param>
        /// <param name="code">The http status.</param>
        /// <returns>Always true.</returns>
        async Task<bool> WriteResponseAsync( JObject o, int code = StatusCodes.Status200OK )
        {
            await Response.WriteAsync( o, code );
            return true;
        }
    }
}
