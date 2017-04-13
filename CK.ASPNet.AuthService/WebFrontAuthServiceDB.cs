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
    public class WebFrontAuthServiceDB : WebFrontAuthService
    {
        readonly IAuthenticationDatabaseService _authPackage;

        public WebFrontAuthServiceDB(IAuthenticationDatabaseService authPackage, IAuthenticationTypeSystem typeSystem )
            : base( typeSystem )
        {
            _authPackage = authPackage;
        }

        /// <summary>
        /// Gets whether the basic authentication is available.
        /// </summary>
        public override bool HasBasicLogin => _authPackage.BasicProvider != null;

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

        IUserInfo ToUserInfo(IUserAuthInfo p)
        {
            return new StdUserInfo( p.UserId, p.UserName, p.Providers.Select( x => new StdUserProviderInfo( x.Name, x.LastUsed)).ToArray() );
        }
    }

}
