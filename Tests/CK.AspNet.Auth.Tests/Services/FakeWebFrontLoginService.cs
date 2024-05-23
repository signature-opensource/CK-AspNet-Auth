using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CK.Auth;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json.Linq;
using CK.Core;

namespace CK.AspNet.Auth.Tests
{
    /// <summary>
    /// Contains 'System (1)', 'Albert (2)', 'Robert (3)' and 'Alice (4)'.
    /// Only Albert and Alice are registered in Basic scheme and can be used by tests. 
    /// </summary>
    class FakeWebFrontLoginService : IWebFrontAuthLoginService
    {
        readonly IAuthenticationTypeSystem _typeSystem;
        readonly List<IUserInfo> _users;

        public FakeWebFrontLoginService( IAuthenticationTypeSystem typeSystem )
        {
            _typeSystem = typeSystem;
            _users = new List<IUserInfo>
            {
                // Albert and Alice are registered in Basic.
                typeSystem.UserInfo.Create( 1, "System" ),
                typeSystem.UserInfo.Create( 2, "Albert", new[] { new StdUserSchemeInfo( "Basic", DateTime.MinValue ) } ),
                typeSystem.UserInfo.Create( 3, "Robert" ),
                typeSystem.UserInfo.Create( 4, "Alice", new[] { new StdUserSchemeInfo( "Basic", DateTime.MinValue ) } )
            };
        }

        public IReadOnlyList<IUserInfo> AllUsers => _users;

        public bool HasBasicLogin => true;

        public IReadOnlyList<string> Providers => new string[] { "Basic" };

        public object CreatePayload( HttpContext ctx, IActivityMonitor monitor, string scheme )
        {
            throw new NotSupportedException();
        }

        public Task<UserLoginResult> BasicLoginAsync( HttpContext ctx, IActivityMonitor monitor, string userName, string password, bool actualLogin )
        {
            IUserInfo? u = null;
            if( password == "success" )
            {
                u = _users.FirstOrDefault( i => i.UserName == userName );
                if( u != null && u.Schemes.Any( p => p.Name == "Basic" ) )
                {
                    _users.Remove( u );
                    u = _typeSystem.UserInfo.Create( u.UserId, u.UserName, new[] { new StdUserSchemeInfo( "Basic", DateTime.UtcNow ) } );
                    _users.Add( u );
                    return Task.FromResult( new UserLoginResult( u, 0, null, false ) );
                }
            }
            return Task.FromResult( new UserLoginResult( null, 1, "Login failed!", false ) );
        }

        public Task<UserLoginResult> LoginAsync( HttpContext ctx, IActivityMonitor monitor, string providerName, object payload, bool actualLogin )
        {
            if( providerName != "Basic" ) throw new ArgumentException( "Unknown provider.", nameof( providerName ) );
            var o = payload as List<(string Key, object Value)>;
            if( o == null ) Throw.ArgumentException( nameof( payload ), "Invalid payload (expected list of (string,object))." );
            return BasicLoginAsync( ctx,
                                    monitor,
                                    (string)o.FirstOrDefault( kv => kv.Key == "userName" ).Value,
                                    (string)o.FirstOrDefault( kv => kv.Key == "password" ).Value,
                                    actualLogin );
        }

        public Task<IAuthenticationInfo> RefreshAuthenticationInfoAsync( HttpContext ctx, IActivityMonitor monitor, IAuthenticationInfo current, DateTime newExpires )
        {
            throw new NotSupportedException( "Not tested." );
        }
    }
}
