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
    public class WebFrontAuthLoginContext
    {
        readonly WebFrontAuthService _authenticationService;
        UserLoginResult _successfulLogin;
        string _errorId;
        string _errorMessage;
        int _loginFailureCode;

        internal WebFrontAuthLoginContext( 
            HttpContext ctx, 
            WebFrontAuthService authService,
            IAuthenticationTypeSystem typeSystem,
            WebFrontAuthLoginMode loginMode,
            string callingScheme,
            AuthenticationProperties authProps,
            string initialScheme, 
            IAuthenticationInfo initialAuth, 
            string returnUrl,
            List<KeyValuePair<string, StringValues>> userData )
        {
            HttpContext = ctx;
            _authenticationService = authService;
            AuthenticationTypeSystem = typeSystem;
            LoginMode = loginMode;
            CallingScheme = callingScheme;
            AuthenticationProperties = authProps;
            InitialScheme = initialScheme;
            InitialAuthentication = initialAuth;
            ReturnUrl = returnUrl;
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
        /// Gets the authentication provider on which .webfront/c/starLogin has been called.
        /// This is "Basic" when <see cref="LoginMode"/> is <see cref="WebFrontAuthLoginMode.BasicLogin"/>. 
        /// </summary>
        public string InitialScheme { get; }

        /// <summary>
        /// Gets the calling authentication scheme.
        /// This is usually the same as the <see cref="InitialScheme"/>.
        /// </summary>
        public string CallingScheme { get; }

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
        /// Gets whether <see cref="SetError"/> or <see cref="SetSuccessfulLogin"/> have been called.
        /// </summary>
        public bool IsHandled => _errorMessage != null || _successfulLogin != null;

        /// <summary>
        /// Sets an error message.
        /// The returned error contains the <paramref name="errorId"/> and <paramref name="errorMessage"/>, the <see cref="InitialScheme"/>, <see cref="CallingScheme"/>
        /// and <see cref="UserData"/>.
        /// Can be called multiple times: new error information replaces the previous one.
        /// </summary>
        /// <param name="errorId">Error identifier (a dotted identifier string).</param>
        /// <param name="errorMessage">The error message in clear text.</param>
        public void SetError( string errorId, string errorMessage )
        {
            if( string.IsNullOrWhiteSpace( errorId ) ) throw new ArgumentNullException( nameof( errorId ) );
            if( string.IsNullOrWhiteSpace( errorMessage ) ) throw new ArgumentNullException( nameof( errorMessage ) );
            _errorId = errorId;
            _errorMessage = errorMessage;
            _loginFailureCode = 0;
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
            _errorMessage = loginFailed.LoginFailureReason;
            _loginFailureCode = loginFailed.LoginFailureCode;
            Debug.Assert( _errorMessage != null );
            Debug.Assert( _loginFailureCode > 0 );
        }

        /// <summary>
        /// Sets a successful login.
        /// Must be called only if no <see cref="SetError(string, string)"/> or <see cref="SetError(UserLoginResult)"/>
        /// have been called before.
        /// </summary>
        /// <param name="user">The logged in user.</param>
        public void SetSuccessfulLogin( UserLoginResult successResult )
        {
            if( successResult == null || !successResult.IsSuccess ) throw new ArgumentException( "Must be a login success.", nameof(successResult) );
            if( _errorMessage != null ) throw new InvalidOperationException( $"An error ({_errorMessage}) has been already set." );
            _successfulLogin = successResult;
        }

        internal Task SendRemoteAuthenticationResponse()
        {
            if( !IsHandled ) throw new InvalidOperationException( "SetError or SetSuccessfulLogin must have been called." );
            if( _errorMessage != null )
            {
                return SendRemoteAuthenticationError();
            }
            return SendRemoteAuthenticationSuccess();
        }

        Task SendRemoteAuthenticationSuccess()
        {
            WebFrontAuthService.LoginResult r = _authenticationService.HandleLogin( HttpContext, _successfulLogin );
            if( ReturnUrl != null )
            {
                // "inline" mode.
                var caller = new Uri( $"{HttpContext.Request.Scheme}://{HttpContext.Request.Host}/" );
                var target = new Uri( caller, ReturnUrl );
                HttpContext.Response.Redirect( target.ToString() );
                return Task.CompletedTask;
            }
            // "popup" mode.
            var data = new JObject(
                            new JProperty( "initialScheme", InitialScheme ),
                            new JProperty( "callingScheme", CallingScheme ) );
            data.Add( UserDataToJProperty() );
            r.Response.Merge( data );
            return HttpContext.Response.WriteWindowPostMessageAsync( r.Response );
        }

        Task SendRemoteAuthenticationError()
        {
            if( ReturnUrl != null )
            {
                int idxQuery = ReturnUrl.IndexOf( '?' );
                var path = idxQuery > 0
                            ? ReturnUrl.Substring( 0, idxQuery )
                            : string.Empty;
                var parameters = idxQuery > 0
                                    ? new QueryString( ReturnUrl.Substring(idxQuery))
                                    : new QueryString();
                parameters = parameters.Add( "errorId", _errorId )
                                       .Add( "errorText", _errorMessage );
                if( _loginFailureCode != 0 ) parameters = parameters.Add( "loginFailureCode", _loginFailureCode.ToString( CultureInfo.InvariantCulture ) );
                if( InitialScheme != null ) parameters = parameters.Add( "initialScheme", InitialScheme );
                if( CallingScheme != null ) parameters = parameters.Add( "callingScheme", CallingScheme );

                var caller = new Uri( $"{HttpContext.Request.Scheme}://{HttpContext.Request.Host}/" );
                var target = new Uri( caller, path + parameters.ToString() );
                HttpContext.Response.Redirect( target.ToString() );
                return Task.CompletedTask;
            }
            else
            {
                return HttpContext.Response.WriteWindowPostMessageWithErrorAsync( _errorId, _errorMessage, _loginFailureCode, InitialScheme, CallingScheme, UserDataToJProperty() );
            }
        }

        JProperty UserDataToJProperty()
        {
            return new JProperty( "userData",
                            new JObject( UserData.Select( d => new JProperty( d.Key,
                                                                              d.Value.Count == 1
                                                                                ? (JToken)d.Value.ToString()
                                                                                : new JArray( d.Value ) ) ) ) );
        }
    }

}
