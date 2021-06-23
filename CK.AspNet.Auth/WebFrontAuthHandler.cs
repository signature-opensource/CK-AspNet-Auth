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
using System.Xml;
using System.Reflection;

namespace CK.AspNet.Auth
{
    sealed class WebFrontAuthHandler : AuthenticationHandler<WebFrontAuthOptions>, IAuthenticationRequestHandler
    {
        readonly static CSemVer.SVersion _version = CSemVer.InformationalVersion.ReadFromAssembly(Assembly.GetExecutingAssembly() ).Version ?? CSemVer.SVersion.ZeroVersion;
        internal readonly static PathString _cSegmentPath = "/c";

        readonly WebFrontAuthService _authService;
        readonly IAuthenticationTypeSystem _typeSystem;
        readonly IWebFrontAuthLoginService _loginService;
        readonly IWebFrontAuthImpersonationService? _impersonationService;
        readonly IWebFrontAuthUnsafeDirectLoginAllowService? _unsafeDirectLoginAllower;

        public WebFrontAuthHandler(
            IOptionsMonitor<WebFrontAuthOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            WebFrontAuthService authService,
            IAuthenticationTypeSystem typeSystem,
            IWebFrontAuthLoginService loginService,
            IWebFrontAuthImpersonationService? impersonationService = null,
            IWebFrontAuthUnsafeDirectLoginAllowService? unsafeDirectLoginAllower = null
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
                        return HandleRefresh( GetRequestMonitor( Context ) );
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
                    if( remainder.Value == "/token" ) return HandleToken( GetRequestMonitor( Context ) );
                }
                return Task.FromResult( true );
            }
            return Task.FromResult( false );
        }

        async Task<bool> HandleRefresh( IActivityMonitor monitor )
        {
            FrontAuthenticationInfo fAuth = await _authService.EnsureAuthenticationInfoAsync( Context, monitor );
            Debug.Assert( fAuth != null );
            if( Request.Query.Keys.Contains( "full" ) )
            {
                var newExpires = DateTime.UtcNow + _authService.CurrentOptions.ExpireTimeSpan;
                fAuth = fAuth.SetInfo( await _loginService.RefreshAuthenticationInfoAsync( Context, GetRequestMonitor( Context ), fAuth.Info, newExpires ) );
            }
            JObject response = GetRefreshResponseAndSetCookies( fAuth, Request.Query.Keys.Contains( "schemes" ), Request.Query.Keys.Contains( "version" ) );
            return await WriteResponseAsync( response );
        }

        JObject GetRefreshResponseAndSetCookies( FrontAuthenticationInfo fAuth, bool addSchemes, bool addVersion )
        {
            var authInfo = fAuth.Info;
            bool refreshable = false;
            if( authInfo.Level >= AuthLevel.Normal && Options.SlidingExpirationTime > TimeSpan.Zero )
            {
                Debug.Assert( authInfo.Expires != null );
                refreshable = true;
                DateTime newExp = DateTime.UtcNow + Options.SlidingExpirationTime;
                if( newExp > authInfo.Expires.Value )
                {
                    fAuth = fAuth.SetInfo( authInfo.SetExpires( newExp ) );
                }
            }
            JObject response = _authService.CreateAuthResponse( Context, fAuth, refreshable );
            if( addSchemes )
            {
                IReadOnlyList<string>? list = Options.AvailableSchemes;
                if( list == null || list.Count == 0 ) list = _loginService.Providers;
                response.Add( "schemes", new JArray( _loginService.Providers ) );
            }
            if( addVersion ) response.Add( "version", _version.ToString() );
            _authService.SetCookies( Context, fAuth );
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
            string rememberMe = Request.Query["rememberMe"];

            IEnumerable<KeyValuePair<string, StringValues>> userData;
            if( HttpMethods.IsPost( Request.Method ) )
            {
                if( callerOrigin == null ) callerOrigin = Request.Form["callerOrigin"];
                if( rememberMe == null ) rememberMe = Request.Form["rememberMe"];
                userData = Request.Form;
            }
            else userData = Request.Query;
            userData = userData.Where( k => !string.Equals( k.Key, "scheme", StringComparison.OrdinalIgnoreCase )
                                            && !string.Equals( k.Key, "returnUrl", StringComparison.OrdinalIgnoreCase )
                                            && !string.Equals( k.Key, "callerOrigin", StringComparison.OrdinalIgnoreCase )
                                            && !string.Equals( k.Key, "rememberMe", StringComparison.OrdinalIgnoreCase ) );

            var fAuthCurrent = await _authService.EnsureAuthenticationInfoAsync( Context, monitor );

            // If "rememberMe" is not found, we keep the previous one (that is false if no current authentication exists).
            // RememberMe defaults to false.
            bool fRememberMe = fAuthCurrent.RememberMe;
            if( rememberMe != null ) fRememberMe = rememberMe == "1" || rememberMe.Equals( "true", StringComparison.OrdinalIgnoreCase );

            var current = fAuthCurrent.Info;
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
                await startContext.SendError( current.DeviceId );
            }
            else
            {
                AuthenticationProperties p = new AuthenticationProperties();
                // This is ugly... but who cares? This is and must remain an implementation detail
                // between this entry point and the ExtractClearWFAData helper method below.
                p.Items.Add( fRememberMe ? "WFA-S" : "WFA-N", current.DeviceId + '|' + startContext.Scheme );
                if( !String.IsNullOrWhiteSpace( startContext.CallerOrigin ) ) p.Items.Add( "WFA-O", startContext.CallerOrigin );
                if( startContext.ReturnUrl != null ) p.Items.Add( "WFA-R", startContext.ReturnUrl );

                if( current.Level != AuthLevel.None ) p.Items.Add( "WFA-C", _authService.ProtectAuthenticationInfo( Context, fAuthCurrent ) );
                else if( startContext.UserData.Count != 0 ) p.Items.Add( "WFA-D", _authService.ProtectExtraData( Context, startContext.UserData ) );
                if( startContext.DynamicScopes != null )
                {
                    p.Parameters.Add( "scope", startContext.DynamicScopes );
                }
                await Context.ChallengeAsync( scheme, p );
            }
            return true;
        }

        internal static void ExtractClearWFAData( AuthenticationProperties props,
                                                  out bool rememberMe,
                                                  out string deviceId,
                                                  out string? initialScheme,
                                                  out string? returnUrl,
                                                  out string? callerOrigin )
        {
            rememberMe = false;
            string? sOrD;
            if( props.Items.TryGetValue( "WFA-S", out sOrD ) )
            {
                rememberMe = true;
            }
            else props.Items.TryGetValue( "WFA-N", out sOrD );

            if( sOrD != null )
            {
                int idx = sOrD.IndexOf( '|' );
                deviceId = sOrD.Substring( 0, idx );
                initialScheme = sOrD.Substring( idx + 1 );
            }
            else
            {
                deviceId = String.Empty;
                initialScheme = null;
            }
            props.Items.TryGetValue( "WFA-R", out returnUrl );
            props.Items.TryGetValue( "WFA-O", out callerOrigin );
        }


        #region Unsafe Direct Login
        class ProviderLoginRequest
        {
            public string Scheme { get; set; }
            public object Payload { get; set; }
            public bool RememberMe { get; set; }
            public Dictionary<string, StringValues> UserData { get; } = new Dictionary<string, StringValues>();

            public ProviderLoginRequest( string scheme, object? payload )
            {
                Scheme = scheme;
                Payload = payload ?? new object();
            }
        }

        async Task<bool> HandleUnsafeDirectLogin( IActivityMonitor monitor )
        {
            Response.StatusCode = StatusCodes.Status403Forbidden;
            if( _unsafeDirectLoginAllower != null )
            {
                string? body = await Request.TryReadSmallBodyAsString( 4096 );
                ProviderLoginRequest? req = body != null ? ReadDirectLoginRequest( monitor, body ) : null;
                if( req != null && await _unsafeDirectLoginAllower.AllowAsync( Context, monitor, req.Scheme, req.Payload ) )
                {
                    var wfaSC = new WebFrontAuthLoginContext(
                                        Context,
                                        _authService,
                                        _typeSystem,
                                        WebFrontAuthLoginMode.UnsafeDirectLogin,
                                        callingScheme: req.Scheme,
                                        req.Payload,
                                        req.RememberMe, 
                                        authProps: null,
                                        req.Scheme,
                                        (await _authService.EnsureAuthenticationInfoAsync( Context, monitor )).Info,
                                        returnUrl: null,
                                        callerOrigin: null,
                                        req.UserData.ToList()
                                        );

                    await _authService.UnifiedLogin( monitor, wfaSC, actualLogin =>
                    {
                        return _loginService.LoginAsync( Context, monitor, req.Scheme, req.Payload, actualLogin );
                    } );
                }
            }
            return true;
        }

        ProviderLoginRequest? ReadDirectLoginRequest( IActivityMonitor monitor, string body )
        {
            ProviderLoginRequest? req = null;
            try
            {
                // By using our poor StringMatcher here, we parse the JSON
                // to basic List<KeyValuePair<string, object>> because 
                // JObject are IEnumerable<KeyValuePair<string, JToken>> and
                // KeyValuePair is not covariant. Moreover JToken is not easily 
                // convertible (to basic types) without using the JToken type.
                // A dependency on NewtonSoft.Json may not be suitable for some 
                // providers.
                var m = new StringMatcher( body );
                if( m.MatchJSONObject( out object val )
                    && val is List<KeyValuePair<string, object>> o )
                {
                    string? provider = o.FirstOrDefault( kv => StringComparer.OrdinalIgnoreCase.Equals( kv.Key, "provider" ) ).Value as string;
                    if( !string.IsNullOrWhiteSpace( provider ) )
                    {
                        req = new ProviderLoginRequest( provider,
                                                        o.FirstOrDefault( kv => StringComparer.OrdinalIgnoreCase.Equals( kv.Key, "payload" ) ).Value );
                        object rem = o.FirstOrDefault( kv => StringComparer.OrdinalIgnoreCase.Equals( kv.Key, "rememberMe" ) ).Value;
                        req.RememberMe = rem != null
                                         && (
                                             ((rem is bool rb) && rb)
                                             ||
                                             (rem is string s && (s == "1" || s.Equals( "true", StringComparison.OrdinalIgnoreCase )))
                                            );
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
            public string? UserName { get; set; }
            public string? Password { get; set; }
            public bool RememberMe { get; set; }
            public Dictionary<string, StringValues> UserData { get; } = new Dictionary<string, StringValues>();
        }

        async Task<bool> DirectBasicLogin( IActivityMonitor monitor )
        {
            Debug.Assert( _loginService.HasBasicLogin );
            string? body  = await Request.TryReadSmallBodyAsString( 4096 );
            BasicLoginRequest? req = body != null ? ReadBasicLoginRequest( monitor, body ) : null;
            if( req != null )
            {
                Debug.Assert( req.UserName != null && req.Password != null );
                var wfaSC = new WebFrontAuthLoginContext(
                    Context,
                    _authService,
                    _typeSystem,
                    WebFrontAuthLoginMode.BasicLogin,
                    "Basic",
                    Tuple.Create( req.UserName, req.Password ),
                    req.RememberMe,
                    authProps: null,
                    initialScheme: "Basic",
                    (await _authService.EnsureAuthenticationInfoAsync( Context, monitor )).Info,
                    returnUrl: null,
                    callerOrigin: null,
                    req.UserData.ToList()
                    ); ; ;

                await _authService.UnifiedLogin( monitor, wfaSC, actualLogin =>
                {
                    return _loginService.BasicLoginAsync( Context, monitor, req.UserName, req.Password, actualLogin );
                } );
            }
            return true;
        }

        BasicLoginRequest? ReadBasicLoginRequest( IActivityMonitor monitor, string body )
        {
            BasicLoginRequest? req = null;
            try
            {
                var r = JsonConvert.DeserializeObject<BasicLoginRequest>( body );
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
            var fAuth = await _authService.EnsureAuthenticationInfoAsync( Context, monitor );
            if( fAuth.Info.ActualUser.UserId != 0 )
            {
                string? body = await Request.TryReadSmallBodyAsString( 1024 );
                int userId = -1;
                string? userName = null;
                if( body != null && TryReadUserKey( monitor, ref userId, ref userName, body ) )
                {
                    if( userName == fAuth.Info.ActualUser.UserName || userId == fAuth.Info.ActualUser.UserId )
                    {
                        fAuth = fAuth.SetInfo( fAuth.Info.ClearImpersonation() );
                        Response.StatusCode = StatusCodes.Status200OK;
                    }
                    else
                    {
                        IUserInfo target = userName != null
                                            ? await _impersonationService.ImpersonateAsync( Context, monitor, fAuth.Info, userName )
                                            : await _impersonationService.ImpersonateAsync( Context, monitor, fAuth.Info, userId );
                        if( target != null )
                        {
                            fAuth = fAuth.SetInfo( fAuth.Info.Impersonate( target ) );
                            Response.StatusCode = StatusCodes.Status200OK;
                        }
                    }
                    if( Response.StatusCode == StatusCodes.Status200OK )
                    {
                        await Response.WriteAsync( GetRefreshResponseAndSetCookies( fAuth, addSchemes: false, addVersion: false ) );
                    }
                }
            }
            return true;
        }

        bool TryReadUserKey( IActivityMonitor monitor, ref int userId, ref string? userName, string body )
        {
            var m = new StringMatcher( body );
            List<KeyValuePair<string, object>>? param;
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
            return false;
        }

        #endregion

        #region Authentication handling (handles standard Authenticate API).

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var monitor = GetRequestMonitor( Context );
            var fAuth = await _authService.EnsureAuthenticationInfoAsync( Context, monitor );
            if( fAuth.Info == null )
            {
                return AuthenticateResult.Fail( "No current Authentication." );
            }           
            var principal = new ClaimsPrincipal();
            principal.AddIdentity( _typeSystem.AuthenticationInfo.ToClaimsIdentity( fAuth.Info, userInfoOnly: !Options.UseFullClaimsPrincipalOnAuthenticate ) );
            var ticket = new AuthenticationTicket( principal, new AuthenticationProperties(), Scheme.Name );
            return AuthenticateResult.Success( ticket );
        }

        #endregion

        async Task<bool> HandleToken( IActivityMonitor monitor )
        {
            var fAuth = await _authService.EnsureAuthenticationInfoAsync( Context, monitor );
            var o = new JObject(
                        new JProperty( "info", _typeSystem.AuthenticationInfo.ToJObject( fAuth.Info ) ),
                        new JProperty( "rememberMe", fAuth.RememberMe ) );
            return await WriteResponseAsync( o );
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
