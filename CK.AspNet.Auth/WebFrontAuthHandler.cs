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

namespace CK.AspNet.Auth
{
    class WebFrontAuthHandler : AuthenticationHandler<WebFrontAuthOptions>, IAuthenticationRequestHandler
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
                            if( HttpMethods.IsPost( Request.Method ) ) return DirectBasicLogin( Context.GetRequestMonitor() );
                            Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
                        }
                    }
                    else if( cBased.Value == "/startLogin" )
                    {
                        return HandleStartLogin();
                    }
                    else if( cBased.Value == "/unsafeDirectLogin" )
                    {
                        if( HttpMethods.IsPost( Request.Method ) ) return HandleUnsafeDirectLogin( Context.GetRequestMonitor() );
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
                            if( HttpMethods.IsPost( Request.Method ) ) return HandleImpersonate( Context.GetRequestMonitor() );
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

        Task<bool> HandleRefresh()
        {
            IAuthenticationInfo authInfo = _authService.EnsureAuthenticationInfo( Context );
            Debug.Assert( authInfo != null );
            JObject response = GetRefreshResponseAndSetCookies( authInfo, Request.Query.Keys.Contains( "schemes" ) );
            return WriteResponseAsync( response );
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

        Task<bool> HandleLogout()
        {
            _authService.Logout( Context );
            Context.Response.StatusCode = StatusCodes.Status200OK;
            return Task.FromResult( true );
        }

        async Task<bool> HandleStartLogin()
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
            await Context.ChallengeAsync( scheme, p );
            return true;
        }

        #region Unsafe Direct Login
        class ProviderLoginRequest
        {
            public string Scheme { get; set; }
            public object Payload { get; set; }
        }

        async Task<bool> HandleUnsafeDirectLogin( IActivityMonitor monitor )
        {
            Response.StatusCode = StatusCodes.Status403Forbidden;
            if( _unsafeDirectLoginAllower != null )
            {
                ProviderLoginRequest req = ReadDirectLoginRequest( monitor );
                if( req != null && await _unsafeDirectLoginAllower.AllowAsync( Context, monitor, req.Scheme, req.Payload ) )
                {
                    try
                    {
                        UserLoginResult u = await _loginService.LoginAsync( Context, monitor, req.Scheme, req.Payload );
                        await DoDirectLogin( u );
                    }
                    catch( ArgumentException ex )
                    {
                        monitor.Error( ex, WebFrontAuthService.WebFrontAuthMonitorTag );
                        await Response.WriteErrorAsync( ex, StatusCodes.Status400BadRequest );
                    }
                    catch( Exception ex )
                    {
                        monitor.Fatal( ex, WebFrontAuthService.WebFrontAuthMonitorTag );
                        throw;
                    }
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
        }

        async Task<bool> DirectBasicLogin( IActivityMonitor monitor )
        {
            Debug.Assert( _loginService.HasBasicLogin );
            BasicLoginRequest req = ReadBasicLoginRequest( monitor );
            if( req != null )
            {
                UserLoginResult u = await _loginService.BasicLoginAsync( Context, monitor, req.UserName, req.Password );
                await DoDirectLogin( u );
            }
            return true;
        }

        BasicLoginRequest ReadBasicLoginRequest( IActivityMonitor monitor )
        {
            BasicLoginRequest req = null;
            try
            {
                string b;
                if( !Request.TryReadSmallBodyAsString( out b, 1024 ) ) return null;
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
                    if( param[0].Key == "userName" && param[0].Value is string )
                    {
                        userName = (string)param[0].Value;
                        return true;
                    }
                    if( param[0].Key == "userId" && param[0].Value is double )
                    {
                        userId = (int)(double)param[0].Value;
                        return true;
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
            principal.AddIdentity( _typeSystem.AuthenticationInfo.ToClaimsIdentity( authInfo, userInfoOnly: false ) );
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
        /// Calls <see cref="WebFrontAuthService.HandleLogin"/> and writes the JSON response.
        /// </summary>
        /// <param name="u">The user info to login.</param>
        /// <returns>Always true.</returns>
        Task<bool> DoDirectLogin( UserLoginResult u )
        {
            WebFrontAuthService.LoginResult r = _authService.HandleLogin( Context, u );
            return WriteResponseAsync( r.Response, r.Info == null ? StatusCodes.Status401Unauthorized : StatusCodes.Status200OK );
        }

        async Task<bool> WriteResponseAsync( JObject o, int code = StatusCodes.Status200OK )
        {
            await Response.WriteAsync( o, code );
            return true;
        }
    }
}
