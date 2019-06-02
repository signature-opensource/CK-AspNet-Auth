using CK.Auth;
using Microsoft.AspNetCore.Http;
#if NETSTANDARD1_6
using Microsoft.AspNetCore.Http.Authentication;
#else
using Microsoft.AspNetCore.Authentication;
#endif
using Microsoft.AspNetCore.Http.Features.Authentication;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Globalization;

namespace CK.AspNet.Auth
{
    /// <summary>
    /// Encapsulates the sign in data issued by an external provider.
    /// </summary>
    internal class WebFrontAuthLoginContext : IWebFrontAuthValidateLoginContext, IWebFrontAuthAutoCreateAccountContext
    {
        readonly WebFrontAuthService _authenticationService;
        UserLoginResult _successfulLogin;
        UserLoginResult _failedLogin;
        string _errorId;
        string _errorText;
        // Used for Direct login (post return code).
        int _httpErrorCode;

        internal WebFrontAuthLoginContext( 
            HttpContext ctx, 
            WebFrontAuthService authService,
            IAuthenticationTypeSystem typeSystem,
            WebFrontAuthLoginMode loginMode,
            string callingScheme,
            object payload,
            AuthenticationProperties authProps,
            string initialScheme, 
            IAuthenticationInfo initialAuth, 
            string returnUrl,
            string callerOrigin,
            List<KeyValuePair<string, StringValues>> userData )
        {
            Debug.Assert( ctx != null && authService != null && typeSystem != null && !String.IsNullOrWhiteSpace( callingScheme ) && payload != null );
            HttpContext = ctx;
            _authenticationService = authService;
            AuthenticationTypeSystem = typeSystem;
            LoginMode = loginMode;
            CallingScheme = callingScheme;
            Payload = payload;
            AuthenticationProperties = authProps;
            InitialScheme = initialScheme;
            InitialAuthentication = initialAuth;
            ReturnUrl = returnUrl;
            CallerOrigin = callerOrigin;
            UserData = userData;
        }

        /// <summary>
        /// Gets the authentication type system.
        /// </summary>
        public IAuthenticationTypeSystem AuthenticationTypeSystem { get; }

        /// <summary>
        /// Gets the current http context.
        /// </summary>
        public HttpContext HttpContext { get; }

        /// <summary>
        /// Gets the endpoint that started the authentication.
        /// </summary>
        public WebFrontAuthLoginMode LoginMode { get; }

        /// <summary>
        /// Gets the Authentication properties.
        /// This is null when <see cref="LoginMode"/> is <see cref="WebFrontAuthLoginMode.BasicLogin"/>
        /// or <see cref="WebFrontAuthLoginMode.UnsafeDirectLogin"/>. 
        /// </summary>
        public AuthenticationProperties AuthenticationProperties { get; }

        /// <summary>
        /// Gets the return url only if '/c/startLogin' has been called with a 'returnUrl' parameter.
        /// Null otherwise.
        /// </summary>
        public string ReturnUrl { get; }

        /// <summary>
        /// Gets the caller scheme and host.
        /// Not null only if '/c/startLogin' has been called.
        /// If startLogin has been called without 'callerOrigin' parameter, this defaults to the request's scheme and host.
        /// </summary>
        public string CallerOrigin { get; }

        /// <summary>
        /// Gets the authentication provider on which .webfront/c/starLogin has been called.
        /// This is "Basic" when <see cref="LoginMode"/> is <see cref="WebFrontAuthLoginMode.BasicLogin"/>
        /// and null when LoginMode is <see cref="WebFrontAuthLoginMode.None"/>. 
        /// </summary>
        public string InitialScheme { get; }

        /// <summary>
        /// Gets the calling authentication scheme.
        /// This is usually the same as the <see cref="InitialScheme"/>.
        /// </summary>
        public string CallingScheme { get; }

        /// <summary>
        /// Gets the provider payload (type is provider dependent).
        /// This is never null but may be an empty object when unsafe login is used with no payload.
        /// </summary>
        public object Payload { get; }

        /// <summary>
        /// Gets the current authentication when .webfront/c/starLogin has been called
        /// or the current authentication when <see cref="LoginMode"/> is <see cref="WebFrontAuthLoginMode.BasicLogin"/>
        /// or <see cref="WebFrontAuthLoginMode.UnsafeDirectLogin"/>.
        /// </summary>
        public IAuthenticationInfo InitialAuthentication { get; }

        /// <summary>
        /// Gets the query (for GET) or form (when POST was used) data of the 
        /// initial .webfront/c/starLogin call as a readonly list.
        /// This is null when <see cref="LoginMode"/> is <see cref="WebFrontAuthLoginMode.BasicLogin"/>
        /// or <see cref="WebFrontAuthLoginMode.UnsafeDirectLogin"/>. 
        /// </summary>
        public IReadOnlyList<KeyValuePair<string, StringValues>> UserData { get; }

        /// <summary>
        /// Gets whether SetError or SetSuccessfulLogin methods have been called.
        /// </summary>
        public bool IsHandled => _errorId != null || _successfulLogin != null;

        /// <summary>
        /// Gets whether an error has already been set.
        /// </summary>
        public bool HasError => _errorId != null;

        /// <summary>
        /// Sets an error message.
        /// The returned error contains the <paramref name="errorId"/> and <paramref name="errorText"/>,
        /// the <see cref="InitialScheme"/>, <see cref="CallingScheme"/> and <see cref="UserData"/>.
        /// Can be called multiple times: new error information replaces the previous one.
        /// </summary>
        /// <param name="errorId">Error identifier (a dotted identifier string). Must not be null or empty.</param>
        /// <param name="errorText">The optional error message in clear text (typically in english).</param>
        public void SetError( string errorId, string errorText = null )
        {
            if( string.IsNullOrWhiteSpace( errorId ) ) throw new ArgumentNullException( nameof( errorId ) );
            _errorId = errorId;
            _errorText = errorText;
            _failedLogin = null;
        }

        UserLoginResult IWebFrontAuthAutoCreateAccountContext.SetError( string errorId, string errorText )
        {
            SetError( errorId, errorText );
            return null;
        }

        /// <summary>
        /// Sets an error message.
        /// The returned error has "errorId" set to the full name of the exception
        /// and the "errorText" is the <see cref="Exception.Message"/>.
        /// Can be called multiple times: new error information replaces the previous one.
        /// </summary>
        /// <param name="ex">The exception.</param>
        public void SetError( Exception ex )
        {
            if( ex == null ) throw new ArgumentNullException( nameof( ex ) );
            _errorId = ex.GetType().FullName;
            _errorText = ex.Message ?? "Exception has null message!";
            if( ex is ArgumentException ) _httpErrorCode = StatusCodes.Status400BadRequest;
            else _httpErrorCode = 0;
            _failedLogin = null;
        }

        UserLoginResult IWebFrontAuthAutoCreateAccountContext.SetError( Exception ex )
        {
            SetError( ex );
            return null;
        }

        /// <summary>
        /// Sets a login failure.
        /// The returned error contains the <see cref="InitialScheme"/>, <see cref="CallingScheme"/>, <see cref="UserData"/>,
        /// the "errorId" is "User.LoginFailure", the "errorMessage" is <see cref="UserLoginResult.LoginFailureReason"/>
        /// and a specific "loginFailureCode" contains the <see cref="UserLoginResult.LoginFailureCode"/>.
        /// Can be called multiple times: new error information replaces the previous one.
        /// </summary>
        /// <param name="loginFailed">Must be not null and <see cref="UserLoginResult.IsSuccess"/> must be false.</param>
        public void SetError( UserLoginResult loginFailed )
        {
            if( loginFailed == null || loginFailed.IsSuccess ) throw new ArgumentException();
            _errorId = "User.LoginFailure";
            _errorText = loginFailed.LoginFailureReason;
            _failedLogin = loginFailed;
            Debug.Assert( _errorText != null );
        }

        /// <summary>
        /// Sets a successful login.
        /// Must be called only if no <see cref="SetError(string, string)"/> or <see cref="SetError(UserLoginResult)"/>
        /// have been called before.
        /// </summary>
        /// <param name="successResult">The result that must be successful.</param>
        public void SetSuccessfulLogin( UserLoginResult successResult )
        {
            if( successResult == null || !successResult.IsSuccess ) throw new ArgumentException( "Must be a login success.", nameof(successResult) );
            if( _errorId != null ) throw new InvalidOperationException( $"An error ({_errorId}) has been already set." );
            _successfulLogin = successResult;
        }

        internal Task SendResponse()
        {
            if( !IsHandled ) throw new InvalidOperationException( "SetError or SetSuccessfulLogin must have been called." );
            if( _errorId != null )
            {
                if( LoginMode == WebFrontAuthLoginMode.UnsafeDirectLogin
                    || LoginMode == WebFrontAuthLoginMode.BasicLogin )
                {
                    return SendDirectAuthenticationError();
                }
                return SendRemoteAuthenticationError();
            }
            WebFrontAuthService.LoginResult r = _authenticationService.HandleLogin( HttpContext, _successfulLogin, CallingScheme );

            if( LoginMode == WebFrontAuthLoginMode.UnsafeDirectLogin
                || LoginMode == WebFrontAuthLoginMode.BasicLogin )
            {
                return SendDirectAuthenticationSuccess( r );
            }
            return SendRemoteAuthenticationSuccess( r );
        }

        Task SendDirectAuthenticationSuccess( WebFrontAuthService.LoginResult r )
        {
            Debug.Assert( r.Info != null );
            if( UserData != null ) r.Response.Add( UserData.ToJProperty() );
            return HttpContext.Response.WriteAsync( r.Response, StatusCodes.Status200OK );
        }

        Task SendDirectAuthenticationError()
        {
            int code = _httpErrorCode == 0 ? StatusCodes.Status401Unauthorized : _httpErrorCode;
            JObject errObj = _authenticationService.CreateErrorAuthResponse( HttpContext, _errorId, _errorText, InitialScheme, CallingScheme, UserData, _failedLogin );
            return HttpContext.Response.WriteAsync( errObj, code );
        }

        Task SendRemoteAuthenticationSuccess( WebFrontAuthService.LoginResult r )
        {
            if( ReturnUrl != null )
            {
                // "inline" mode.
                var caller = new Uri( CallerOrigin );
                var target = new Uri( caller, ReturnUrl );
                HttpContext.Response.Redirect( target.ToString() );
                return Task.CompletedTask;
            }
            // "popup" mode.
            var data = new JObject(
                            new JProperty( "initialScheme", InitialScheme ),
                            new JProperty( "callingScheme", CallingScheme ) );
            data.Add( UserData.ToJProperty() );
            r.Response.Merge( data );
            return HttpContext.Response.WriteWindowPostMessageAsync( r.Response, CallerOrigin );
        }

        Task SendRemoteAuthenticationError()
        {
            return _authenticationService.SendRemoteAuthenticationError(
                        HttpContext,
                        ReturnUrl,
                        CallerOrigin,
                        _errorId,
                        _errorText,
                        InitialScheme,
                        CallingScheme,
                        UserData,
                        _failedLogin );
        }
    }

}
