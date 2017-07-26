using CK.Auth;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.AspNetCore.Http.Features.Authentication;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace CK.AspNet.Auth
{
    /// <summary>
    /// Encapsulates the sign in data issued by an external provider.
    /// </summary>
    public class WebFrontAuthSignInContext
    {
        string _errorId;
        string _errorMessage;
        IUserInfo _successfulLogin;

        internal WebFrontAuthSignInContext( 
            HttpContext ctx, 
            WebFrontAuthService authService,
            IAuthenticationTypeSystem typeSystem,
            string callingScheme,
            AuthenticationProperties authProps,
            ClaimsPrincipal principal,
            string initialScheme, 
            IAuthenticationInfo initialAuth, 
            string returnUrl,
            List<KeyValuePair<string, StringValues>> userData )
        {
            HttpContext = ctx;
            AuthenticationService = authService;
            AuthenticationTypeSystem = typeSystem;
            CallingScheme = callingScheme;
            AuthenticationProperties = authProps;
            InitialScheme = initialScheme;
            InitialAuthentication = initialAuth;
            ReturnUrl = returnUrl;
            UserData = userData;
        }

        /// <summary>
        /// Gets the authentication service.
        /// </summary>
        public WebFrontAuthService AuthenticationService { get; }

        /// <summary>
        /// Gets the authentication type system.
        /// </summary>
        public IAuthenticationTypeSystem AuthenticationTypeSystem { get; }

        /// <summary>
        /// Gets the current http context.
        /// </summary>
        public HttpContext HttpContext { get; }

        /// <summary>
        /// Gets the Authentication properties.
        /// </summary>
        public AuthenticationProperties AuthenticationProperties { get; }

        /// <summary>
        /// Gets the return url if '/c/startLogin' has been called with a 'returnUrl' parameter.
        /// </summary>
        public string ReturnUrl { get; }

        /// <summary>
        /// Gets the ClaimsPrincipal.
        /// </summary>
        public ClaimsPrincipal Principal { get; }

        /// <summary>
        /// Gets the authentication provider on which .webfront/c/starLogin has been called.
        /// </summary>
        public string InitialScheme { get; }

        /// <summary>
        /// Gets the calling authentication scheme.
        /// </summary>
        public string CallingScheme { get; }

        /// <summary>
        /// Gets the current authentication when .webfront/c/starLogin has been called.
        /// </summary>
        public IAuthenticationInfo InitialAuthentication { get; }

        /// <summary>
        /// Gets the query (fer GET) or form (when POST was used) data of the 
        /// initial .webfront/c/starLogin call as a readonly list.
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
        /// </summary>
        /// <param name="errorId">Error identifier (a dotted identifier string).</param>
        /// <param name="errorMessage">The error message in clear text.</param>
        public void SetError( string errorId, string errorMessage )
        {
            _errorId = errorId;
            _errorMessage = errorMessage;
        }

        /// <summary>
        /// Sets a successful login.
        /// </summary>
        /// <param name="user">The logged in user.</param>
        public void SetSuccessfulLogin( IUserInfo user )
        {
            if( _errorMessage != null ) throw new InvalidOperationException();
            _successfulLogin = user;
        }

        public Task SendResponse()
        {
            if( !IsHandled ) throw new InvalidOperationException( "SetError or SetSuccessfulLogin must have been called." );
            if( _errorMessage != null )
            {
                return SendError();
            }
            return SendSuccess();
        }

        Task SendSuccess()
        {
            var data = new JObject(
                            new JProperty( "u", AuthenticationTypeSystem.UserInfo.ToJObject( _successfulLogin ) ),
                            new JProperty( "initialScheme", InitialScheme ),
                            new JProperty( "callingScheme", CallingScheme ) );
            if( ReturnUrl == null )
            {
                data.Add( UserDataToJProperty() );
            }
            string secure = AuthenticationService.ProtectString( 
                                    HttpContext, 
                                    data.ToString( Newtonsoft.Json.Formatting.None ), 
                                    TimeSpan.FromSeconds( 3 ) );
            return HttpContext.Response.WritePostRedirectEndLoginAsync( secure, ReturnUrl );
        }

        Task SendError()
        {
            if( ReturnUrl != null )
            {
                HttpContext.Response.RedirectToReturnUrlWithError( ReturnUrl, _errorId, _errorMessage, InitialScheme, CallingScheme );
                return Task.CompletedTask;
            }
            else
            {
                return HttpContext.Response.WritePostMessageWithErrorAsync( _errorId, _errorMessage, InitialScheme, CallingScheme, UserDataToJProperty() );
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
