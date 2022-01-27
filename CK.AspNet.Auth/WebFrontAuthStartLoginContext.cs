using CK.Auth;
using CK.Core;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CK.AspNet.Auth
{

    /// <summary>
    /// Captures initial login request information and provides a context to interact with the flow
    /// before challenging the actual remote authentication.
    /// </summary>
    public sealed class WebFrontAuthStartLoginContext : IErrorContext
    {
        readonly WebFrontAuthService _webFrontAuthService;
        readonly FrontAuthenticationInfo _currentAuth;
        string? _errorId;
        string? _errorText;

        internal WebFrontAuthStartLoginContext( HttpContext ctx,
                                                WebFrontAuthService authService,
                                                string? scheme,
                                                FrontAuthenticationInfo current,
                                                bool impersonateActualUser,
                                                IEnumerable<KeyValuePair<string, StringValues>> userData,
                                                string? returnUrl,
                                                string? callerOrigin )
        {
            Debug.Assert( ctx != null && authService != null );
            Debug.Assert( scheme != null );
            Debug.Assert( current != null );
            Debug.Assert( userData != null );
            HttpContext = ctx;
            _webFrontAuthService = authService;
            _currentAuth = current;
            // will be validated below.
            Scheme = scheme ?? String.Empty;
            UserData = new Dictionary<string, StringValues>();
            foreach( var d in userData ) UserData.Add( d.Key, d.Value );
            ReturnUrl = returnUrl;
            CallerOrigin = callerOrigin;
            ImpersonateActualUser = impersonateActualUser;
        }

        internal void ValidateStartLoginRequest( IActivityMonitor monitor )
        {
            if( string.IsNullOrWhiteSpace( Scheme ) )
            {
                SetError( "RequiredSchemeParameter", "A scheme parameter is required." );
                return;
            }
            _webFrontAuthService.ValidateCoreParameters( monitor, WebFrontAuthLoginMode.StartLogin, ReturnUrl, CallerOrigin, Current, ImpersonateActualUser, this );
        }

        /// <summary>
        /// Gets the http context.
        /// </summary>
        public HttpContext HttpContext { get; }

        /// <summary>
        /// Gets the current authentication.
        /// </summary>
        public IAuthenticationInfo Current => _currentAuth.Info;

        /// <summary>
        /// Gets whether the authentication should be memorized (or be as transient as possible).
        /// Note that this is always false when <see cref="AuthenticationCookieMode.None"/> is used.
        /// </summary>
        public bool RememberMe => _currentAuth.RememberMe;

        /// <summary>
        /// Gets the scheme to challenge.
        /// Never null or empty.
        /// </summary>
        public string Scheme { get; }

        /// <summary>
        /// Gets the return url. Not null if and only if "inline login" is used.
        /// This url is always checked against the <see cref="WebFrontAuthOptions.AllowedReturnUrls"/> set of allowed prefixes. 
        /// </summary>
        public string? ReturnUrl { get; set; }

        /// <summary>
        /// Gets the caller origin. Not null if and only if "popup login" is used.
        /// </summary>
        public string? CallerOrigin { get; }

        /// <summary>
        /// Gets or sets whether the login wants to keep the previous logged in user as the <see cref="IAuthenticationInfo.ActualUser"/>
        /// and becomes the <see cref="IAuthenticationInfo.User"/>.
        /// </summary>
        public bool ImpersonateActualUser { get; set; }

        /// <summary>
        /// Gets the mutable user data.
        /// </summary>
        public IDictionary<string, StringValues> UserData { get; }

        /// <summary>
        /// Gets whether an error has been set.
        /// </summary>
        public bool HasError => _errorId != null;

        /// <summary>
        /// Sets an error message.
        /// The returned error contains the <paramref name="errorId"/> and <paramref name="errorMessage"/>, the <see cref="Scheme"/>
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
            _errorText = errorMessage;
        }

        /// <summary>
        /// Captures dynamic scopes from optional IWebFrontAuthDynamicScopeProvider.GetScopesAsync call.
        /// This is internal since it is the optional <see cref="IWebFrontAuthDynamicScopeProvider"/> that is used
        /// to set it from <see cref="WebFrontAuthService.OnHandlerStartLoginAsync(Core.IActivityMonitor, WebFrontAuthStartLoginContext)"/>.
        /// </summary>
        internal string[]? DynamicScopes;

        internal Task SendErrorAsync()
        {
            Debug.Assert( HasError );
            Debug.Assert( _errorId != null && _errorText != null );

            return _webFrontAuthService.SendRemoteAuthenticationErrorAsync(
                        HttpContext,
                        _currentAuth,
                        ReturnUrl,
                        CallerOrigin,
                        _errorId,
                        _errorText,
                        Scheme,
                        null,
                        UserData,
                        null );
        }

    }

}
