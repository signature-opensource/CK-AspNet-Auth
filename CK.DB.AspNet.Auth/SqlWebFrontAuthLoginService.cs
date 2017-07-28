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

namespace CK.DB.AspNet.Auth
{

    /// <summary>
    /// Implements <see cref="IWebFrontAuthLoginService"/> bond to a <see cref="IAuthenticationDatabaseService"/>.
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
        public async Task<IUserInfo> BasicLoginAsync( HttpContext ctx, IActivityMonitor monitor, string userName, string password )
        {
            var c = ctx.GetSqlCallContext( monitor );
            int userId = await _authPackage.BasicProvider.LoginUserAsync( c, userName, password );
            return userId > 0
                    ? _typeSystem.UserInfo.FromUserAuthInfo( await _authPackage.ReadUserAuthInfoAsync( c, 1, userId ) )
                    : null;
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
        /// <returns>The <see cref="IUserInfo"/> or null.</returns>
        public async Task<IUserInfo> LoginAsync( HttpContext ctx, IActivityMonitor monitor, string scheme, object payload )
        {
            IGenericAuthenticationProvider p = FindProvider( scheme, false );
            var c = ctx.GetSqlCallContext( monitor );
            int userId = await p.LoginUserAsync( c, payload );
            return userId > 0
                    ? _typeSystem.UserInfo.FromUserAuthInfo( await _authPackage.ReadUserAuthInfoAsync( c, 1, userId ) )
                    : null;
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
