using CK.AspNet;
using CK.AspNet.Auth;
using CK.Auth;
using CK.Core;
using CK.DB.Actor;
using CK.DB.Auth;
using CK.SqlServer;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace WebApp
{
    public class AutoCreateAccountService : IWebFrontAuthAutoCreateAccountService
    {
        readonly UserTable _userTable;
        readonly IAuthenticationDatabaseService _dbAuth;
        readonly IAuthenticationTypeSystem _typeSystem;

        public AutoCreateAccountService( UserTable userTable, IAuthenticationDatabaseService dbAuth, IAuthenticationTypeSystem typeSystem )
        {
            _userTable = userTable;
            _dbAuth = dbAuth;
            _typeSystem = typeSystem;
        }

        public async Task<UserLoginResult> CreateAccountAndLoginAsync( IActivityMonitor monitor, IWebFrontAuthAutoCreateAccountContext context )
        {
            //
            // This is for OpenIdConnectTests.Bob_login_on_webfront_returns_User_NoAutoRegistration test.
            // Bob must not be created in the database.
            if( context.CallingScheme == "oidc" ) return null;
            ISqlCallContext ctx = context.HttpContext.GetSqlCallContext();
            int idUser = await _userTable.CreateUserAsync( ctx, 1, Guid.NewGuid().ToString() );
            IGenericAuthenticationProvider p = _dbAuth.FindProvider( context.CallingScheme );
            UCLResult dbResult = await p.CreateOrUpdateUserAsync( ctx, 1, idUser, context.Payload, UCLMode.CreateOnly | UCLMode.WithActualLogin );
            if( dbResult.OperationResult != UCResult.Created ) return null;
            return await _dbAuth.CreateUserLoginResultFromDatabase( ctx, _typeSystem, dbResult.LoginResult );
        }
    }
}
