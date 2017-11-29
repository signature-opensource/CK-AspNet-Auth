using CK.DB.Auth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CK.SqlServer;
using CK.Core;

namespace CK.DB.AspNet.Auth.Tests
{
    public class MockAuthDatabaseService : IAuthenticationDatabaseService
    {
        IBasicAuthenticationProvider _basic;
        IGenericAuthenticationProvider _basicAdapter;
        readonly List<IGenericAuthenticationProvider> _providers = new List<IGenericAuthenticationProvider>();
        readonly List<MockAuthUser> _users = new List<MockAuthUser>();

        public MockAuthDatabaseService( bool withBasic = true, bool withGoogleGeneric = true)
        {
            if (withGoogleGeneric) _providers.Add(new MockAuthGenericService(this, "Google"));
            if (withBasic) BasicProvider = new MockAuthBasicProvider(this);
            _users.Add(new MockAuthUser() { UserId = 1, UserName = "System" });

            var albertIsRegisteredInBasic = new MockAuthUser()
            {
                UserId = 2,
                UserName = "Albert"
            };
            albertIsRegisteredInBasic.Schemes.Add( new UserAuthSchemeInfo("Basic", Util.UtcMinValue) );
            _users.Add(albertIsRegisteredInBasic);
            _users.Add(new MockAuthUser() { UserId = 3, UserName = "Robert" });
            _users.Add(new MockAuthUser() { UserId = 4, UserName = "Hubert" });
        }

        public IBasicAuthenticationProvider BasicProvider
        {
            get => _basic;
            set
            {
                if (_basicAdapter != null) _providers.Remove(_basicAdapter);
                _basic = value;
                _basicAdapter = _basic != null ? new BasicToGenericProviderAdapter(_basic) : null;
                if (_basicAdapter != null) _providers.Add(_basicAdapter);
            }
        }

        public List<IGenericAuthenticationProvider> GenericProviders => _providers;

        public List<MockAuthUser> Users => _users;

        public IReadOnlyCollection<IGenericAuthenticationProvider> AllProviders => _providers;


        public IGenericAuthenticationProvider FindProvider(string providerName)
        {
            return _providers.FirstOrDefault(p => StringComparer.OrdinalIgnoreCase.Equals(p.ProviderName, providerName));
        }

        public IUserAuthInfo ReadUserAuthInfo(ISqlCallContext ctx, int actorId, int userId)
        {
            return _users.FirstOrDefault( u => u.UserId == userId );
        }

        public Task<IUserAuthInfo> ReadUserAuthInfoAsync(ISqlCallContext ctx, int actorId, int userId)
        {
            return Task.FromResult( (IUserAuthInfo)_users.FirstOrDefault(u => u.UserId == userId) );
        }

        /// <summary>
        /// Implements <see cref="IGenericAuthenticationProvider"/> on <see cref="Users"/>.
        /// </summary>
        /// <param name="userId">The user identifier. Must exist.</param>
        /// <param name="mode">Creation/update mode.</param>
        /// <param name="providerName">The provider name.</param>
        /// <returns>The create result.</returns>
        public UCLResult CreateOrUpdateUser(int userId, UCLMode mode, string providerName)
        {
            MockAuthUser user = _users.FirstOrDefault(u => u.UserId == userId);
            if (user == null) throw new Exception("Invalid user identifier.");
            int idx = user.Schemes.IndexOf(p => p.Name == providerName);
            bool actualLogin = (mode & UCLMode.WithActualLogin) != 0;
            var loginTime = Util.UtcMinValue;
            if (idx < 0)
            {
                if( (mode & UCLMode.UpdateOnly) == 0 ) return new UCLResult( 0, UCResult.None, null, 0 );
                user.Schemes.Add(new UserAuthSchemeInfo(providerName, actualLogin ? DateTime.UtcNow : Util.UtcMinValue));
                return new UCLResult( userId, UCResult.Created, null, 0 ); ;
            }
            if ((mode & UCLMode.CreateOnly) == 0) return new UCLResult( 0, UCResult.None, null, 0 );
            user.Schemes[idx] = new UserAuthSchemeInfo(providerName, actualLogin ? DateTime.UtcNow : user.Schemes[idx].LastUsed);
            return new UCLResult( userId, UCResult.Updated, null, 0 ); ;
        }

        /// <summary>
        /// Destroys a user for a provider.
        /// </summary>
        /// <param name="userId">User identifier.</param>
        /// <param name="providerName">The provider name.</param>
        public void DestroyUser(int userId, string providerName)
        {
            MockAuthUser user = _users.FirstOrDefault(u => u.UserId == userId);
            if (user != null)
            {
                int idx = user.Schemes.IndexOf(p => p.Name == providerName);
                if (idx >= 0) user.Schemes.RemoveAt(idx);
            }
        }

        /// <summary>
        /// Challenge a user login for a provider.
        /// Whenever the user is registered in the provider and password is not "failed", it succeeds.
        /// </summary>
        /// <param name="userName">The user name.</param>
        /// <param name="password">The password.</param>
        /// <param name="actualLogin">True to update provider's last used.</param>
        /// <param name="providerName">The provider name.</param>
        /// <returns>The user identifier or 0 on failure.</returns>
        public LoginResult LoginUser(string userName, string password, bool actualLogin, string providerName)
        {
            if (password == "failed") return new LoginResult( KnownLoginFailureCode.InvalidCredentials );
            MockAuthUser user = _users.FirstOrDefault(u => u.UserName == userName);
            if (user == null) return new LoginResult( KnownLoginFailureCode.InvalidUserKey );
            int idx = user.Schemes.IndexOf(p => p.Name == providerName);
            if (idx < 0) new LoginResult( KnownLoginFailureCode.UnregisteredUser );
            if (actualLogin) user.Schemes[idx] = new UserAuthSchemeInfo(user.Schemes[idx].Name, DateTime.UtcNow);
            return new LoginResult( user.UserId );
        }
        /// <summary>
        /// Challenge a user login for a provider.
        /// Whenever the user is registered in the provider and password is not "failed", it succeeds.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <param name="password">The password.</param>
        /// <param name="actualLogin">True to update provider's last used.</param>
        /// <param name="providerName">The provider name.</param>
        /// <returns>The user identifier or 0 on failure.</returns>
        public LoginResult LoginUser(int userId, string password, bool actualLogin, string providerName)
        {
            if (password == "failed") return new LoginResult(KnownLoginFailureCode.InvalidCredentials);
            MockAuthUser user = _users.FirstOrDefault(u => u.UserId == userId);
            if (user == null) return new LoginResult( KnownLoginFailureCode.InvalidUserKey );
            int idx = user.Schemes.IndexOf(p => p.Name == providerName);
            if (idx < 0) new LoginResult( KnownLoginFailureCode.UnregisteredUser );
            if (actualLogin) user.Schemes[idx] = new UserAuthSchemeInfo(user.Schemes[idx].Name, DateTime.UtcNow);
            return new LoginResult( userId );
        }

    }
}
