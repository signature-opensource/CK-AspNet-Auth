using CK.AspNet;
using CK.AspNet.Auth;
using CK.Auth;
using CK.Core;
using CK.DB.Auth;
using CK.SqlServer;
using CK.SqlServer.Setup;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace CK.DB.AspNet.Auth
{
    /// <summary>
    /// Specialized <see cref="WebFrontAuthService"/> that interfaces <see cref="IAuthenticationDatabaseService"/>.
    /// </summary>
    public class SqlWebFrontAuthService : WebFrontAuthService
    {
        readonly IAuthenticationDatabaseService _authPackage;
        readonly IReadOnlyList<string> _providers;

        /// <summary>
        /// Initializes a new <see cref="SqlWebFrontAuthService"/>.
        /// </summary>
        /// <param name="authPackage">The database service to use.</param>
        /// <param name="typeSystem">The authentication type sytem to use.</param>
        public SqlWebFrontAuthService(IAuthenticationDatabaseService authPackage, IAuthenticationTypeSystem typeSystem )
            : base( typeSystem )
        {
            if (authPackage == null) throw new ArgumentNullException(nameof(authPackage));
            _authPackage = authPackage;
            _providers = _authPackage.AllProviders.Select(p => p.ProviderName).ToArray();
        }

        /// <summary>
        /// Gets whether the basic authentication is available.
        /// </summary>
        public override bool HasBasicLogin => _authPackage.BasicProvider != null;

        /// <summary>
        /// Gets the existing providers's name.
        /// </summary>
        public override IReadOnlyList<string> Providers => _providers;

        /// <summary>
        /// Attempts to login. If it fails, null is returned. <see cref="HasBasicLogin"/> must be true for this
        /// to be called.
        /// </summary>
        /// <param name="ctx">Current Http context.</param>
        /// <param name="userName">The user name.</param>
        /// <param name="password">The password.</param>
        /// <returns>The <see cref="IUserInfo"/> or null.</returns>
        public override async Task<IUserInfo> BasicLoginAsync(HttpContext ctx, string userName, string password)
        {
            var c = ctx.GetSqlCallContext();
            int userId = await _authPackage.BasicProvider.LoginUserAsync(c, userName, password);
            return userId > 0
                    ? ToUserInfo(await _authPackage.ReadUserAuthInfoAsync(c, 1, userId))
                    : null;
        }

        /// <summary>
        /// Attempts to login a user using an existing provider.
        /// The provider must exist and the payload must be compatible otherwise an <see cref="ArgumentException"/>
        /// is thrown.
        /// </summary>
        /// <param name="ctx">Current Http context.</param>
        /// <param name="providerName">The provider name to use.</param>
        /// <param name="payload">The provider dependent login payload.</param>
        /// <returns>The <see cref="IUserInfo"/> or null.</returns>
        public override async Task<IUserInfo> LoginAsync(HttpContext ctx, string providerName, object payload)
        {
            IGenericAuthenticationProvider p = _authPackage.FindProvider(providerName);
            if (p == null) throw new ArgumentException("Unknown provider.", nameof(providerName));
            var c = ctx.GetSqlCallContext();
            int userId = await p.LoginUserAsync(c, payload);
            return userId > 0
                    ? ToUserInfo(await _authPackage.ReadUserAuthInfoAsync(c, 1, userId))
                    : null;
        }

        IUserInfo ToUserInfo(IUserAuthInfo p)
        {
            return AuthenticationTypeSystem.UserInfo.Create( 
                p.UserId, 
                p.UserName, 
                p.Schemes.Select( x => new StdUserSchemeInfo( x.Name, x.LastUsed)).ToArray() );
        }
    }

}
