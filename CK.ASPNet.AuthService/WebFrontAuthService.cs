using CK.Auth;
using CK.DB.Auth;
using CK.SqlServer;
using CK.SqlServer.Setup;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CK.AspNet.AuthService
{
    public class WebFrontAuthService
    {
        readonly IAuthenticationDatabaseService _authPackage;
        readonly IAuthenticationTypeSystem _typeSystem;

        public WebFrontAuthService(IAuthenticationDatabaseService authPackage, IAuthenticationTypeSystem typeSystem )
        {
            _authPackage = authPackage;
            _typeSystem = typeSystem;
        }

        public bool HasBasicLogin => _authPackage.BasicProvider != null;

        /// <summary>
        /// Exposes the <see cref="IAuthenticationTypeSystem"/> used to handle authentication info 
        /// conversions.
        /// </summary>
        public IAuthenticationTypeSystem AuthenticationTypeSystem => _typeSystem;

        /// <summary>
        /// Attempts to login. If it fails, null is returned.
        /// </summary>
        /// <param name="ctx">The call context to use.</param>
        /// <param name="userName">The user name.</param>
        /// <param name="password">The password.</param>
        /// <returns>The <see cref="IUserInfo"/> or null.</returns>
        public async Task<IUserInfo> BasicLoginAsync(ISqlCallContext ctx, string userName, string password)
        {
            int userId = await _authPackage.BasicProvider.LoginUserAsync(ctx, userName, password);
            return userId > 0
                    ? ToUserInfo( await _authPackage.ReadUserAuthInfoAsync(ctx, 1, userId))
                    : null;
        }

        private IUserInfo ToUserInfo(IUserAuthInfo p)
        {
            return new StdUserInfo( p.UserId, p.UserName, p.Providers.Select( x => new StdUserProviderInfo( x.Name, x.LastUsed)).ToArray() );
        }
    }

}
