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

namespace CK.DB.AspNet.Auth
{
    public class AutoBindingAccountService : IWebFrontAuthAutoBindingAccountService
    {
        private readonly IAuthenticationDatabaseService _authPackage;
        private readonly IAuthenticationTypeSystem _typeSystem;
        private readonly IReadOnlyList<string> _providers;
        private readonly SqlDefaultDatabase _defaultDatabase;

        public AutoBindingAccountService( IAuthenticationDatabaseService authPackage, IAuthenticationTypeSystem typeSystem, SqlDefaultDatabase defaultDatabase)
        {
            _authPackage = authPackage;
            _typeSystem = typeSystem;
            _providers = _authPackage.AllProviders.Select( p => p.ProviderName ).ToArray();
            _defaultDatabase = defaultDatabase;
        }

        public async Task<AccountBindingResult> BindAccountAsync( IActivityMonitor monitor, IWebFrontAuthAutoBindingAccountContext context )
        {
            //IAuthenticationInfo authenticationInfo = context.InitialAuthentication;
            //bool error = authenticationInfo.User.Schemes.Any<IUserSchemeInfo>( scheme => (scheme.Name == context.InitialScheme) );
            //if( error )
            //{
            //    return null;
            //}

            using ( var sqlCtx = new SqlStandardCallContext() )
            {
                IGenericAuthenticationProvider p = FindProvider( context.InitialScheme, true );
                UCLResult result  = await p.CreateOrUpdateUserAsync( sqlCtx, 1, context.InitialAuthentication.User.UserId, context.Payload, UCLMode.UpdateOnly );
                return await _authPackage.CreateAccountBindingResultFromDatabase( sqlCtx, _typeSystem, result.LoginResult );
            }
        }

        protected virtual IGenericAuthenticationProvider FindProvider( string scheme, bool mustHavePayload )
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
