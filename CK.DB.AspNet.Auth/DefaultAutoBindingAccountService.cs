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
    /// Default implementation that will bind account as long as the currently logged
    /// user is <see cref="AuthLevel.Critical"/>.
    /// </summary>
    public class DefaultAutoBindingAccountService : IWebFrontAuthAutoBindingAccountService
    {
        private readonly IAuthenticationDatabaseService _authPackage;

        public DefaultAutoBindingAccountService( IAuthenticationDatabaseService authPackage )
        {
            _authPackage = authPackage;
        }

        public async Task<UserLoginResult> BindAccountAsync( IActivityMonitor monitor, IWebFrontAuthAutoBindingAccountContext context )
        {
            if( context.InitialAuthentication.Level != AuthLevel.Critical )
            {
                return context.SetError( "User.AccountBinding.CriticalLevelRequired", "User must be logged in Critical level." );
            }
            IGenericAuthenticationProvider p = _authPackage.FindRequiredProvider( context.CallingScheme );
            var ctx = context.HttpContext.RequestServices.GetRequiredService<ISqlCallContext>();
            UCLResult result  = await p.CreateOrUpdateUserAsync( ctx, 1, context.InitialAuthentication.User.UserId, context.Payload, UCLMode.CreateOrUpdate );
            return await _authPackage.CreateUserLoginResultFromDatabase( ctx, context.AuthenticationTypeSystem, result.LoginResult );
        }
    }
}
