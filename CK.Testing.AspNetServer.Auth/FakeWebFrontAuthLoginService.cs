using System.Threading.Tasks;
using CK.AspNet.Auth;
using System.Collections.Generic;
using CK.Auth;
using CK.Core;
using Microsoft.AspNetCore.Http;
using System.Linq;
using System;

namespace CK.Testing;

/// <summary>
/// Fake login service bound to the <see cref="FakeUserDatabase"/> that
/// implements only "Basic" login based on the <see cref="FakeUserDatabase.AllUsers"/> availability
/// and password "success" for every existing users.
/// <para>
/// This class can be totally specialized.
/// </para>
/// </summary>
[ExcludedCKType]
public class FakeWebFrontAuthLoginService : IWebFrontAuthLoginService
{
    readonly IAuthenticationTypeSystem _typeSystem;
    readonly FakeUserDatabase _userDB;

    /// <summary>
    /// Initializes a new <see cref="FakeWebFrontAuthLoginService"/>.
    /// </summary>
    /// <param name="typeSystem">The authentication type system.</param>
    /// <param name="userDB">The fake user database.</param>
    public FakeWebFrontAuthLoginService( IAuthenticationTypeSystem typeSystem, FakeUserDatabase userDB )
    {
        _typeSystem = typeSystem;
        _userDB = userDB;
    }

    /// <summary>
    /// Gets the fake user database.
    /// </summary>
    public FakeUserDatabase UserDatabase => _userDB;

    /// <inheritdoc />
    /// <remarks>
    /// This default implementation always returns true.
    /// </remarks>
    public virtual bool HasBasicLogin => true;

    /// <inheritdoc />
    /// <remarks>
    /// This default implementation returns "Basic".
    /// </remarks>
    public virtual IReadOnlyList<string> Providers => ["Basic"];

    /// <inheritdoc />
    /// <remarks>
    /// This default implementation expect only the "Basic" <paramref name="scheme"/> and returns a <c>List&lt;(string, object?)&gt;</c>
    /// that should be filled with a "userName" and "password" key-value pairs before calling <see cref="LoginAsync(HttpContext, IActivityMonitor, string, object, bool)"/>.
    /// <para>
    /// Any other scheme throws a <see cref="ArgumentException"/>.
    /// </para>
    /// </remarks>
    public virtual object CreatePayload( HttpContext ctx, IActivityMonitor monitor, string scheme )
    {
        if( scheme == "Basic" )
        {
            return new List<(string, object?)>();
        }
        throw new ArgumentException( $"Unknown scheme '{scheme}'." );
    }

    /// <inheritdoc />
    /// <remarks>
    /// This default implementation succeeds for every user of the <see cref="UserDatabase"/> registered in "Basic" provider
    /// when the password is "success".
    /// </remarks>
    public virtual Task<UserLoginResult> BasicLoginAsync( HttpContext ctx, IActivityMonitor monitor, string userName, string password, bool actualLogin )
    {
        IUserInfo? u = null;
        if( password == "success" )
        {
            u = _userDB.AllUsers.FirstOrDefault( i => i.UserName == userName );
            if( u != null && u.Schemes.Any( p => p.Name == "Basic" ) )
            {
                _userDB.AllUsers.Remove( u );
                u = _typeSystem.UserInfo.Create( u.UserId, u.UserName, new[] { new UserSchemeInfo( "Basic", DateTime.UtcNow ) } );
                _userDB.AllUsers.Add( u );
            }
            return Task.FromResult( new UserLoginResult( u, 0, null, false ) );
        }
        return Task.FromResult( new UserLoginResult( null, 1, "Login failed!", false ) );
    }

    /// <inheritdoc />
    /// <remarks>
    /// This default implementation only handles the "Basic" <c>List&lt;KeyValuePair&lt;string, object&gt;&gt;</c> payload
    /// and calls <see cref="BasicLoginAsync(HttpContext, IActivityMonitor, string, string, bool)"/>.
    /// </remarks>
    public virtual Task<UserLoginResult> LoginAsync( HttpContext ctx, IActivityMonitor monitor, string providerName, object payload, bool actualLogin )
    {
        Throw.CheckArgument( "Only Basic is supported.", providerName == "Basic" );
        if( payload is not List<(string Key, object Value)> o ) throw new ArgumentException( "Invalid payload (expected list of (string,object)).", nameof( payload ) );
        return BasicLoginAsync( ctx,
                                monitor,
                                (string)o.FirstOrDefault( kv => kv.Key == "userName" ).Value,
                                (string)o.FirstOrDefault( kv => kv.Key == "password" ).Value,
                                actualLogin );
    }

    /// <inheritdoc />
    /// <remarks>
    /// This default implementation is a standard implementation of a refresh based on the existence of the <paramref name="current"/> <see cref="IAuthenticationInfo.ActualUser"/>
    /// in the database.
    /// </remarks>
    public virtual Task<IAuthenticationInfo> RefreshAuthenticationInfoAsync( HttpContext ctx, IActivityMonitor monitor, IAuthenticationInfo current, DateTime newExpires )
    {
        current = current.CheckExpiration();
        if( current.Level < AuthLevel.Normal )
        {
            return Task.FromResult( current );
        }
        var stillHere = _userDB.AllUsers.FirstOrDefault( i => i.UserName == current.ActualUser.UserName );
        if( stillHere != null )
        {
            monitor.Info( $"Refreshed authentication for '{current.ActualUser.UserName}'." );
            return Task.FromResult( current.SetExpires( newExpires ) );
        }
        monitor.Info( $"Failed to refresh authentication for '{current.ActualUser.UserName}'." );
        current = _typeSystem.AuthenticationInfo.Create( current.ActualUser, deviceId: current.DeviceId );
        return Task.FromResult( current );
    }
}
