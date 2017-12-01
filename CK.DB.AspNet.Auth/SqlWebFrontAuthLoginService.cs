using CK.AspNet.Auth;
using System;
using System.Collections.Generic;
using System.Text;
using CK.Auth;
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;
using CK.DB.Auth;
using System.Linq;
using CK.AspNet;
using CK.Text;
using CK.Core;
using System.Diagnostics;
using CK.SqlServer;

namespace CK.DB.AspNet.Auth
{

    /// <summary>
    /// Implements <see cref="IWebFrontAuthLoginService"/> bousnd to a <see cref="IAuthenticationDatabaseService"/>.
    /// </summary>
    public class SqlWebFrontAuthLoginService : IWebFrontAuthLoginService
    {
        readonly IAuthenticationDatabaseService _authPackage;
        readonly IAuthenticationTypeSystem _typeSystem;
        readonly IReadOnlyList<string> _providers;

        /// <summary>
        /// Initializes a new <see cref="SqlWebFrontAuthLoginService"/>.
        /// </summary>
        /// <param name="authPackage">The database service to use.</param>
        /// <param name="typeSystem">The authentication type sytem to use.</param>
        public SqlWebFrontAuthLoginService( IAuthenticationDatabaseService authPackage, IAuthenticationTypeSystem typeSystem )
        {
            if( authPackage == null ) throw new ArgumentNullException( nameof( authPackage ) );
            _authPackage = authPackage;
            _typeSystem = typeSystem;
            _providers = _authPackage.AllProviders.Select( p => p.ProviderName ).ToArray();
        }

        /// <summary>
        /// Gets whether the basic authentication is available.
        /// </summary>
        public bool HasBasicLogin => _authPackage.BasicProvider != null;

        /// <summary>
        /// Gets the existing providers's name.
        /// </summary>
        public IReadOnlyList<string> Providers => _providers;

        /// <summary>
        /// Attempts to login. If it fails, null is returned. <see cref="HasBasicLogin"/> must be true for this
        /// to be called.
        /// </summary>
        /// <param name="ctx">Current Http context.</param>
        /// <param name="monitor">The activity monitor to use.</param>
        /// <param name="userName">The user name.</param>
        /// <param name="password">The password.</param>
        /// <returns>The <see cref="IUserInfo"/> or null.</returns>
        public async Task<UserLoginResult> BasicLoginAsync( HttpContext ctx, IActivityMonitor monitor, string userName, string password )
        {
            var c = ctx.GetSqlCallContext( monitor );
            LoginResult r = await _authPackage.BasicProvider.LoginUserAsync( c, userName, password );
            return await CreateUserLoginResultFromDatabase( c, r ); 
        }

        async Task<UserLoginResult> CreateUserLoginResultFromDatabase( ISqlCallContext ctx, LoginResult dbResult )
        {
            IUserInfo info = dbResult.IsSuccess
                                ? _typeSystem.UserInfo.FromUserAuthInfo( await _authPackage.ReadUserAuthInfoAsync( ctx, 1, dbResult.UserId ) )
                                : null;
            return new UserLoginResult( info, dbResult.FailureCode, dbResult.FailureReason, dbResult.FailureCode == (int)KnownLoginFailureCode.UnregisteredUser );
        }

        /// <summary>
        /// Creates a payload object for a given scheme that can be used to 
        /// call <see cref="LoginAsync"/>.
        /// </summary>
        /// <param name="ctx">Current Http context.</param>
        /// <param name="monitor">The activity monitor to use.</param>
        /// <param name="scheme">The login scheme (either the provider name to use or starts with the provider name and a dot).</param>
        /// <returns>A new, empty, provider dependent login payload.</returns>
        public object CreatePayload( HttpContext ctx, IActivityMonitor monitor, string scheme )
        {
            return FindProvider( scheme, mustHavePayload: true ).CreatePayload();
        }

        /// <summary>
        /// Attempts to login a user using a scheme.
        /// A provider for the scheme must exist and the payload must be compatible otherwise an <see cref="ArgumentException"/>
        /// is thrown.
        /// </summary>
        /// <param name="ctx">Current Http context.</param>
        /// <param name="monitor">The activity monitor to use.</param>
        /// <param name="scheme">The scheme to use.</param>
        /// <param name="payload">The provider dependent login payload.</param>
        /// <returns>The login result.</returns>
        public async Task<UserLoginResult> LoginAsync( HttpContext ctx, IActivityMonitor monitor, string scheme, object payload )
        {
            IGenericAuthenticationProvider p = FindProvider( scheme, false );
            var c = ctx.GetSqlCallContext( monitor );
            LoginResult r = await p.LoginUserAsync( c, payload );
            return await CreateUserLoginResultFromDatabase( c, r );
        }

        IGenericAuthenticationProvider FindProvider( string scheme, bool mustHavePayload )
        {
            IGenericAuthenticationProvider p = _authPackage.FindProvider( scheme );
            if( p == null ) throw new ArgumentException( $"Unable to find a database provider for scheme '{scheme}'. Available: {_providers.Concatenate()}.", nameof( scheme ) );
            if( mustHavePayload && !p.HasPayload() )
            {
                throw new ArgumentException( $"Database provider '{p.GetType().FullName}' does not handle generic payload." );
            }
            return p;
        }
    }
}
