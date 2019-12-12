using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using CK.AspNet.Auth;
using CK.Auth;
using CK.Core;
using CK.DB.Auth;
using System.Linq;
using CK.SqlServer;
using CK.Text;
using Microsoft.Extensions.DependencyInjection;

namespace CK.DB.AspNet.Auth
{
    /// <summary>
    /// Default implementation that will bind accounts as long as the currently logged
    /// user is <see cref="AuthLevel.Critical"/> (but this can be changed).
    /// </summary>
    public class DefaultAutoBindingAccountService : IWebFrontAuthAutoBindingAccountService
    {
        readonly IAuthenticationDatabaseService _authPackage;
        readonly bool _useCritical;

        /// <summary>
        /// Initializes a new <see cref="DefaultAutoBindingAccountService"/>.
        /// </summary>
        /// <param name="authPackage">The authentication database service.</param>
        /// <param name="useCriticalLevel">By default, Critical level is expected.</param>
        public DefaultAutoBindingAccountService( IAuthenticationDatabaseService authPackage, bool useCriticalLevel = true )
        {
            _authPackage = authPackage;
            _useCritical = useCriticalLevel;
        }

        /// <summary>
        /// Called for each failed login when the user is currently logged in and
        /// calls <see cref="IGenericAuthenticationProvider.CreateOrUpdateUser(ISqlCallContext, int, int, object, UCLMode)"/> to bind
        /// a new provider to the user.
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="context">Account binding context.</param>
        /// <returns>
        /// The login result where the <see cref="IUserInfo.Schemes"/> contains the new scheme.
        /// </returns>
        public async Task<UserLoginResult> BindAccountAsync( IActivityMonitor monitor, IWebFrontAuthAutoBindingAccountContext context )
        {
            if( monitor == null ) throw new ArgumentNullException( nameof( monitor ) );
            if( context == null ) throw new ArgumentNullException( nameof( context ) );
            var auth = context.InitialAuthentication;
            if( auth.IsNullOrNone() ) throw new ArgumentNullException( nameof( context.InitialAuthentication ) );
            if( auth.IsImpersonated ) throw new ArgumentException( "Invalid impersonation.", nameof( context.InitialAuthentication ) );

            if( auth.Level < AuthLevel.Normal )
            {
                return context.SetError( "User.AccountBinding.AtLeastNormalLevelRequired", "User must be logged at least in Normal level." );
            }
            if( _useCritical && auth.Level != AuthLevel.Critical )
            {
                return context.SetError( "User.AccountBinding.CriticalLevelRequired", "User must be logged in Critical level." );
            }
            IGenericAuthenticationProvider p = _authPackage.FindRequiredProvider( context.CallingScheme );
            var ctx = context.HttpContext.RequestServices.GetRequiredService<ISqlCallContext>();
            UCLResult result  = await p.CreateOrUpdateUserAsync( ctx, 1, auth.User.UserId, context.Payload, UCLMode.CreateOrUpdate );
            return await _authPackage.CreateUserLoginResultFromDatabase( ctx, context.AuthenticationTypeSystem, result.LoginResult );
        }
    }
}
