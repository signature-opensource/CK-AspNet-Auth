using CK.AspNet.Auth;
using CK.Auth;
using CK.Core;
using CK.DB.Auth;
using CK.SqlServer;
using CK.SqlServer.Setup;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace CK.DB.AspNet.Auth
{
    public class SqlWebFrontAuthService : WebFrontAuthService
    {
        readonly IAuthenticationDatabaseService _authPackage;
        readonly IReadOnlyList<string> _providers;

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
        /// <param name="userName">The user name.</param>
        /// <param name="password">The password.</param>
        /// <returns>The <see cref="IUserInfo"/> or null.</returns>
        public override async Task<IUserInfo> BasicLoginAsync( string userName, string password)
        {
            using (var ctx = new SqlStandardCallContext())
            {
                int userId = await _authPackage.BasicProvider.LoginUserAsync(ctx, userName, password);
                return userId > 0
                        ? ToUserInfo(await _authPackage.ReadUserAuthInfoAsync(ctx, 1, userId))
                        : null;
            }
        }

        /// <summary>
        /// Attempts to login a user using an existing provider.
        /// The provider must exist and the payload must be compatible otherwise an <see cref="ArgumentException"/>
        /// is thrown.
        /// </summary>
        /// <param name="providerName">The provider name to use.</param>
        /// <param name="payload">The provider dependent login payload.</param>
        /// <returns>The <see cref="IUserInfo"/> or null.</returns>
        public override async Task<IUserInfo> LoginAsync(string providerName, object payload)
        {
            IGenericAuthenticationProvider p = _authPackage.FindProvider(providerName);
            if (p == null) throw new ArgumentException("Unknown provider.", nameof(providerName));
            using (var ctx = new SqlStandardCallContext())
            {
                int userId = await p.LoginUserAsync(ctx, payload);
                return userId > 0
                        ? ToUserInfo(await _authPackage.ReadUserAuthInfoAsync(ctx, 1, userId))
                        : null;
            }
        }

        IUserInfo ToUserInfo(IUserAuthInfo p)
        {
            return AuthenticationTypeSystem.UserInfo.Create( p.UserId, p.UserName, p.Providers.Select( x => new StdUserProviderInfo( x.Name, x.LastUsed)).ToArray() );
        }
    }

}
