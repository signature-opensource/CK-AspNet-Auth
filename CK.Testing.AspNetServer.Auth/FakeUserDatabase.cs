using System.Threading.Tasks;
using CK.Core;
using System.Collections.Generic;
using CK.Auth;
using System.Linq;
using System;

namespace CK.Testing;

/// <summary>
/// Fake user database that contains "System" (1), "Alice" (3711), "Albert" (3712), "Robert" (3713) and "Hubert" (3714).
/// "Alice", "Albert" and "Hubert" have the "Basic" provider.
/// "Hubert" has the "Google" provider.
/// <para>
/// <see cref="AllUsers"/> is totally mutable and everything is virtual.
/// </para>
/// </summary>
[ExcludeCKType]
public class FakeUserDatabase : IUserInfoProvider
{
    readonly List<IUserInfo> _users;
    readonly IAuthenticationTypeSystem _typeSystem;

    public FakeUserDatabase( IAuthenticationTypeSystem typeSystem )
    {
        _users =
        [
            typeSystem.UserInfo.Create( 1, "System" ),
            typeSystem.UserInfo.Create( 3711, "Alice", [new StdUserSchemeInfo( "Basic", DateTime.MinValue )] ),
            typeSystem.UserInfo.Create( 3712, "Albert", [new StdUserSchemeInfo( "Basic", DateTime.MinValue )] ),
            typeSystem.UserInfo.Create( 3713, "Robert" ),
            typeSystem.UserInfo.Create( 3714, "Hubert", [new StdUserSchemeInfo( "Basic", DateTime.MinValue ), new StdUserSchemeInfo( "Google", DateTime.MinValue )] )
        ];
        _typeSystem = typeSystem;
    }

    public virtual IList<IUserInfo> AllUsers => _users;

    public virtual ValueTask<IUserInfo> GetUserInfoAsync( IActivityMonitor monitor, int userId )
    {
        var u = _users.FirstOrDefault( u => u.UserId == userId ) ?? _typeSystem.UserInfo.Anonymous;
        return ValueTask.FromResult( u );
    }
}
