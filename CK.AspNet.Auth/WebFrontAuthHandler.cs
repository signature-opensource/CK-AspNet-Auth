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
using Newtonsoft.Json;
using Microsoft.AspNetCore.Authentication;
using System.Globalization;
using Microsoft.Extensions.DependencyInjection;
using System.Xml;
using System.Reflection;
using ISystemClock = Microsoft.AspNetCore.Authentication.ISystemClock;
using System.Text.Json;

namespace CK.AspNet.Auth
{
    sealed class WebFrontAuthHandler : AuthenticationHandler<WebFrontAuthOptions>, IAuthenticationRequestHandler
    {
        readonly static CSemVer.SVersion _version = CSemVer.InformationalVersion.ReadFromAssembly(Assembly.GetExecutingAssembly() ).Version ?? CSemVer.SVersion.ZeroVersion;
        internal readonly static PathString _cSegmentPath = "/c";

        readonly WebFrontAuthService _authService;
        readonly IAuthenticationTypeSystem _typeSystem;
        readonly IWebFrontAuthLoginService _loginService;
        readonly IAuthenticationSchemeProvider _schemeProvider;
        readonly IWebFrontAuthImpersonationService? _impersonationService;
        readonly IWebFrontAuthUnsafeDirectLoginAllowService? _unsafeDirectLoginAllower;

        public WebFrontAuthHandler( IOptionsMonitor<WebFrontAuthOptions> options,
                                    ILoggerFactory logger,
                                    UrlEncoder encoder,
                                    ISystemClock clock,
                                    WebFrontAuthService authService,
                                    IAuthenticationTypeSystem typeSystem,
                                    IWebFrontAuthLoginService loginService,
                                    IAuthenticationSchemeProvider schemeProvider,
                                    IWebFrontAuthImpersonationService? impersonationService = null,
                                    IWebFrontAuthUnsafeDirectLoginAllowService? unsafeDirectLoginAllower = null ) : base( options, logger, encoder, clock )
        {
            _authService = authService;
            _typeSystem = typeSystem;
            _loginService = loginService;
            _schemeProvider = schemeProvider;
            _impersonationService = impersonationService;
            _unsafeDirectLoginAllower = unsafeDirectLoginAllower;
        }

        IActivityMonitor GetRequestMonitor( HttpContext c ) => c.RequestServices.GetRequiredService<IActivityMonitor>();

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
                        return HandleRefreshAsync();
                    }
                    else if( cBased.Value == "/basicLogin" )
                    {
                        if( _loginService.HasBasicLogin )
                        {
                            if( HttpMethods.IsPost( Request.Method ) ) return DirectBasicLoginAsync( GetRequestMonitor( Context ) );
                            Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
                        }
                    }
                    else if( cBased.Value == "/startLogin" )
                    {
                        return HandleStartLoginAsync( GetRequestMonitor( Context ) );
                    }
                    else if( cBased.Value == "/unsafeDirectLogin" )
                    {
                        if( HttpMethods.IsPost( Request.Method ) ) return HandleUnsafeDirectLoginAsync( GetRequestMonitor( Context ) );
                        Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
                    }
                    else if( cBased.Value == "/logout" )
                    {
                        return HandleLogoutAsync();
                    }
                    else if( cBased.Value == "/impersonate" )
                    {
                        // When _impersonationService == null, we only support
                        // impersonation to the ActualUser itself: this clears any current impersonation.
                        if( HttpMethods.IsPost( Request.Method ) ) return HandleImpersonateAsync( GetRequestMonitor( Context ) );
                        Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
                    }
                }
                else
                {
                    if( remainder.Value == "/token" ) return HandleTokenAsync();
                }
                return Task.FromResult( true );
            }
            return Task.FromResult( false );
        }

        async Task<bool> HandleRefreshAsync()
        {
            IActivityMonitor? monitor = null;
            FrontAuthenticationInfo fAuth = _authService.EnsureAuthenticationInfo( Context, ref monitor );
            Debug.Assert( fAuth != null );
            if( _authService.CurrentOptions.AlwaysCallBackendOnRefresh || Request.Query.Keys.Contains( "callBackend" ) )
            {
                var newExpires = DateTime.UtcNow + _authService.CurrentOptions.ExpireTimeSpan;
                monitor ??= GetRequestMonitor( Context );
                fAuth = fAuth.SetInfo( await _loginService.RefreshAuthenticationInfoAsync( Context, monitor, fAuth.Info, newExpires ) );
            }
            JObject response = await GetRefreshResponseAndSetCookiesAsync( fAuth, Request.Query.Keys.Contains( "schemes" ), Request.Query.Keys.Contains( "version" ) );
            return await WriteResponseAsync( response );
        }

        /// <summary>
        /// Applies the <see cref="WebFrontAuthOptions.SlidingExpirationTime"/> (if not 0), handles the <paramref name="addSchemes"/>
        /// and <paramref name="addVersion"/> and sets the cookies.
        /// </summary>
        /// <param name="fAuth">The authentication.</param>
        /// <param name="addSchemes">Whether authentications schemes must be returned.</param>
        /// <param name="addVersion">Whether this assembly's version should be returned.</param>
        /// <returns>The JSON object.</returns>
        async ValueTask<JObject> GetRefreshResponseAndSetCookiesAsync( FrontAuthenticationInfo fAuth, bool addSchemes, bool addVersion )
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
            JObject response = _authService.CreateAuthResponse( Context, refreshable, fAuth );
            if( addSchemes )
            {
                IEnumerable<string>? list = Options.AvailableSchemes;
                if( list == null || !list.Any() )
                {
                    list = (await _schemeProvider.GetAllSchemesAsync().ConfigureAwait(false))
                            .Select( s => s.Name )
                            .Where( n => n != WebFrontAuthOptions.OnlyAuthenticationScheme );
                    if( _loginService.HasBasicLogin )
                    {
                        list = list.Prepend( "Basic" );
                    }
                }
                response.Add( "schemes", new JArray( list ) );
            }
            if( addVersion ) response.Add( "version", _version.ToString() );
            _authService.SetCookies( Context, fAuth );
            return response;
        }

        async Task<bool> HandleLogoutAsync()
        {
            _authService.Logout( Context );
            await Context.Response.WriteAsync( null, StatusCodes.Status200OK );
            return true;
        }

        async Task<bool> HandleStartLoginAsync( IActivityMonitor monitor )
        {
            string scheme = Request.Query["scheme"];
            if( scheme == null )
            {
                Response.StatusCode = StatusCodes.Status400BadRequest;
                return true;
            }
            string? returnUrl = Request.Query["returnUrl"];
            string? callerOrigin = Request.Query["callerOrigin"];
            string? rememberMe = Request.Query["rememberMe"];
            string? sImpersonateActualUser = Request.Query["impersonateActualUser"];

            IEnumerable<KeyValuePair<string, StringValues>> userData;
            if( HttpMethods.IsPost( Request.Method ) )
            {
                if( callerOrigin == null ) callerOrigin = Request.Form["callerOrigin"];
                if( rememberMe == null ) rememberMe = Request.Form["rememberMe"];
                if( sImpersonateActualUser == null ) sImpersonateActualUser = Request.Form["impersonateActualUser"];
                userData = Request.Form;
            }
            else userData = Request.Query;
            userData = userData.Where( k => !string.Equals( k.Key, "scheme", StringComparison.OrdinalIgnoreCase )
                                            && !string.Equals( k.Key, "returnUrl", StringComparison.OrdinalIgnoreCase )
                                            && !string.Equals( k.Key, "callerOrigin", StringComparison.OrdinalIgnoreCase )
                                            && !string.Equals( k.Key, "rememberMe", StringComparison.OrdinalIgnoreCase )
                                            && !string.Equals( k.Key, "impersonateActualUser", StringComparison.OrdinalIgnoreCase ) );

            var fAuthCurrent = _authService.EnsureAuthenticationInfo( Context, ref monitor );

            // If "rememberMe" is not found, we keep the previous one (that is false if no current authentication exists).
            // RememberMe defaults to false.
            if( rememberMe != null )
            {
                fAuthCurrent.SetRememberMe( rememberMe == "1" || rememberMe.Equals( "true", StringComparison.OrdinalIgnoreCase ) );
            }

            bool impersonateActualUser = sImpersonateActualUser != null && (sImpersonateActualUser == "1" || sImpersonateActualUser.Equals( "true", StringComparison.OrdinalIgnoreCase ));

            var startContext = new WebFrontAuthStartLoginContext( Context, _authService, scheme, fAuthCurrent, impersonateActualUser, userData, returnUrl, callerOrigin );
            // We test impersonation here: login is forbidden whenever the user is impersonated.
            // This check will also be done by WebFrontAuthService.UnifiedLogin.
            if( fAuthCurrent.Info.IsImpersonated && !impersonateActualUser )
            {
                startContext.SetError( "LoginWhileImpersonation", "Login is not allowed while impersonation is active." );
                monitor.Error( WebFrontAuthService.WebFrontAuthMonitorTag, $"Login is not allowed while impersonation is active: {fAuthCurrent.Info.ActualUser.UserId} impersonated into {fAuthCurrent.Info.User.UserId}." );
            }
            else
            {
                await _authService.OnHandlerStartLoginAsync( monitor, startContext );
            }
            if( startContext.HasError )
            {
                await startContext.SendErrorAsync();
            }
            else
            {
                AuthenticationProperties p = new AuthenticationProperties();
                _authService.SetWFAData( p, fAuthCurrent, startContext.ImpersonateActualUser, startContext.Scheme, startContext.CallerOrigin, startContext.ReturnUrl, startContext.UserData );
                if( startContext.DynamicScopes != null )
                {
                    // This is how wanted OAuth scope are transfered to the target.
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
            public bool RememberMe { get; set; }
            public bool ImpersonateActualUser { get; set; }
            public Dictionary<string, StringValues> UserData { get; } = new Dictionary<string, StringValues>();

            public ProviderLoginRequest( string scheme, object? payload )
            {
                Scheme = scheme;
                Payload = payload ?? new object();
            }
        }

        async Task<bool> HandleUnsafeDirectLoginAsync( IActivityMonitor monitor )
        {
            Response.StatusCode = StatusCodes.Status403Forbidden;
            if( _unsafeDirectLoginAllower != null )
            {
                string? body = await Request.TryReadSmallBodyAsStringAsync( 4096 );
                ProviderLoginRequest? req = body != null ? ReadDirectLoginRequest( monitor, body ) : null;
                if( req != null
                    && await _unsafeDirectLoginAllower.AllowAsync( Context, monitor, req.Scheme, req.Payload ) )
                {
                    var wfaSC = new WebFrontAuthLoginContext(
                                        Context,
                                        _authService,
                                        _typeSystem,
                                        WebFrontAuthLoginMode.UnsafeDirectLogin,
                                        callingScheme: req.Scheme,
                                        req.Payload,
                                        authProps: null,
                                        req.Scheme,
                                        _authService.EnsureAuthenticationInfo( Context, ref monitor ).SetRememberMe( req.RememberMe ),
                                        req.ImpersonateActualUser,
                                        returnUrl: null,
                                        callerOrigin: null,
                                        req.UserData.ToList()
                                        );

                    await _authService.UnifiedLoginAsync( monitor, wfaSC, actualLogin =>
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
                //var root = JsonDocument.Parse( body ).RootElement;
                //var provider = root.GetString( "provider" );
                //if( provider != null )
                //{
                //    var payload = root.GetProperty( "payload" );
                //    req = new ProviderLoginRequest( provider, payload );
                //    req.RememberMe = root.GetProperty( "rememberMe" ).ValueKind == JsonValueKind.True;
                //    var userData = root.GetProperty( "userData" );
                //    if( userData.ValueKind == JsonValueKind.Object )
                //    {
                //        foreach( var prop in userData.EnumerateObject() )
                //        {
                //            prop.Value.
                //        }
                //    }

                //}
                // By using our poor StringMatcher here, we parse the JSON
                // to basic List<KeyValuePair<string, object>> because 
                // JObject are IEnumerable<KeyValuePair<string, JToken>> and
                // KeyValuePair is not covariant. Moreover JToken is not easily 
                // convertible (to basic types) without using the JToken type.
                // A dependency on NewtonSoft.Json may not be suitable for some 
                // providers.


                var m = new ROSpanCharMatcher( body );
                if( m.TryMatchAnyJSON( out object? val )
                    && val is List<(string Key, object? Value)> o )
                {
                    string? provider = o.FirstOrDefault( kv => StringComparer.OrdinalIgnoreCase.Equals( kv.Key, "provider" ) ).Value as string;
                    if( !string.IsNullOrWhiteSpace( provider ) )
                    {
                        req = new ProviderLoginRequest( provider,
                                                        o.FirstOrDefault( kv => StringComparer.OrdinalIgnoreCase.Equals( kv.Key, nameof( ProviderLoginRequest.Payload ) ) ).Value );
                        object? rem = o.FirstOrDefault( kv => StringComparer.OrdinalIgnoreCase.Equals( kv.Key, nameof( ProviderLoginRequest.RememberMe ) ) ).Value;
                        req.RememberMe = rem != null
                                         && (
                                             ((rem is bool rb) && rb)
                                             ||
                                             (rem is string s && (s == "1" || s.Equals( "true", StringComparison.OrdinalIgnoreCase )))
                                            );
                        object? imp = o.FirstOrDefault( kv => StringComparer.OrdinalIgnoreCase.Equals( kv.Key, nameof( ProviderLoginRequest.ImpersonateActualUser ) ) ).Value;
                        req.ImpersonateActualUser = imp != null
                                         && (
                                             ((imp is bool ri) && ri)
                                             ||
                                             (imp is string sI && (sI == "1" || sI.Equals( "true", StringComparison.OrdinalIgnoreCase )))
                                            );
                        var userData = o.FirstOrDefault( kv => StringComparer.OrdinalIgnoreCase.Equals( kv.Key, nameof( ProviderLoginRequest.UserData ) ) ).Value;
                        if( userData is List<(string Key, object Value)> data )
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
                monitor.Error( WebFrontAuthService.WebFrontAuthMonitorTag, "Invalid payload.", ex );
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
            public bool ImpersonateActualUser { get; set; }
            public Dictionary<string, StringValues> UserData { get; } = new Dictionary<string, StringValues>();
        }

        async Task<bool> DirectBasicLoginAsync( IActivityMonitor monitor )
        {
            Debug.Assert( _loginService.HasBasicLogin );
            string? body  = await Request.TryReadSmallBodyAsStringAsync( 4096 );
            BasicLoginRequest? req = body != null ? ReadBasicLoginRequest( monitor, body ) : null;
            if( req != null )
            {
                Debug.Assert( req.UserName != null && req.Password != null );
                var wfaSC = new WebFrontAuthLoginContext( Context,
                                                          _authService,
                                                          _typeSystem,
                                                          WebFrontAuthLoginMode.BasicLogin,
                                                          "Basic",
                                                          Tuple.Create( req.UserName, req.Password ),
                                                          authProps: null,
                                                          initialScheme: "Basic",
                                                          _authService.EnsureAuthenticationInfo( Context, ref monitor ).SetRememberMe( req.RememberMe ),
                                                          req.ImpersonateActualUser,
                                                          returnUrl: null,
                                                          callerOrigin: null,
                                                          req.UserData.ToList() );

                await _authService.UnifiedLoginAsync( monitor, wfaSC, actualLogin =>
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
        async Task<bool> HandleImpersonateAsync( IActivityMonitor monitor )
        {
            Debug.Assert( HttpMethods.IsPost( Request.Method ) );
            Response.StatusCode = _impersonationService == null ? StatusCodes.Status404NotFound : StatusCodes.Status403Forbidden;
            var fAuth = _authService.EnsureAuthenticationInfo( Context, ref monitor );
            if( fAuth.Info.ActualUser.UserId != 0 )
            {
                string? body = await Request.TryReadSmallBodyAsStringAsync( 1024 );
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
                        if( _impersonationService != null )
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
                    }
                    if( Response.StatusCode == StatusCodes.Status200OK )
                    {
                        await Response.WriteAsync( await GetRefreshResponseAndSetCookiesAsync( fAuth, addSchemes: false, addVersion: false ) );
                    }
                }
            }
            return true;
        }

        bool TryReadUserKey( IActivityMonitor monitor, ref int userId, ref string? userName, string body )
        {
            var m = new ROSpanCharMatcher( body );
            List<(string Key, object? Value)>? param;
            if( m.TryMatchAnyJSON( out object? val )
                && (param = val as List<(string, object?)>) != null
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

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            IActivityMonitor? monitor = null;
            var fAuth = _authService.EnsureAuthenticationInfo( Context, ref monitor );
            if( fAuth.Info == null )
            {
                return Task.FromResult( AuthenticateResult.Fail( "No current Authentication." ) );
            }           
            var principal = new ClaimsPrincipal();
            principal.AddIdentity( _typeSystem.AuthenticationInfo.ToClaimsIdentity( fAuth.Info, userInfoOnly: !Options.UseFullClaimsPrincipalOnAuthenticate ) );
            var ticket = new AuthenticationTicket( principal, new AuthenticationProperties(), Scheme.Name );
            return Task.FromResult( AuthenticateResult.Success( ticket ) );
        }

        #endregion

        Task<bool> HandleTokenAsync()
        {
            IActivityMonitor? monitor = null;
            var fAuth = _authService.EnsureAuthenticationInfo( Context, ref monitor );
            var o = new JObject(
                        new JProperty( "info", _typeSystem.AuthenticationInfo.ToJObject( fAuth.Info ) ),
                        new JProperty( "rememberMe", fAuth.RememberMe ) );
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
