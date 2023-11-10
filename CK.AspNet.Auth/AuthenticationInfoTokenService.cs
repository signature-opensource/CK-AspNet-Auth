using CK.Auth;
using CK.Core;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using System;
using System.Diagnostics;

namespace CK.AspNet.Auth
{
    /// <summary>
    /// Simple singleton service that offers tokens creation and restoration functionalities.
    /// <para>
    /// This is not a endpoint service, it is available from all endpoints.
    /// </para>
    /// </summary>
    public sealed class AuthenticationInfoTokenService : ISingletonAutoService
    {
        readonly IAuthenticationTypeSystem _typeSystem;
        readonly IDataProtector _baseDataProtector;
        readonly IDataProtector _tokenDataProtector;
        readonly FrontAuthenticationInfoSecureDataFormat _frontTokenFormat;

        public AuthenticationInfoTokenService( IAuthenticationTypeSystem typeSystem, IDataProtectionProvider dataProtectionProvider )
        {
            _typeSystem = typeSystem;
            Debug.Assert( typeof( WebFrontAuthHandler ).FullName == "CK.AspNet.Auth.WebFrontAuthHandler" );
            _baseDataProtector = dataProtectionProvider.CreateProtector( "CK.AspNet.Auth.WebFrontAuthHandler" );
            _tokenDataProtector = _baseDataProtector.CreateProtector( "Token", "v1" );
            _frontTokenFormat = new FrontAuthenticationInfoSecureDataFormat( _typeSystem, _tokenDataProtector );
        }

        /// <summary>
        /// Gets the type system service.
        /// </summary>
        public IAuthenticationTypeSystem TypeSystem => _typeSystem;

        /// <summary>
        /// Gets the data protector to use for authentication tokens.
        /// </summary>
        public IDataProtector TokenDataProtector => _tokenDataProtector;

        /// <summary>
        /// Base data protector for authentication related protected data.
        /// </summary>
        public IDataProtector BaseDataProtector => _baseDataProtector;

        /// <summary>
        /// Creates a token from a <see cref="FrontAuthenticationInfo"/>.
        /// </summary>
        /// <param name="info">The authentication info.</param>
        /// <returns>The url-safe secured authentication token string.</returns>
        public string ProtectFrontAuthenticationInfo( FrontAuthenticationInfo info )
        {
            Debug.Assert( info.Info != null );
            return _frontTokenFormat.Protect( info );
        }

        /// <summary>
        /// Extracts a <see cref="FrontAuthenticationInfo"/> from a token previously created with <see cref="ProtectFrontAuthenticationInfo(FrontAuthenticationInfo)"/>.
        /// <para>
        /// By default, the expiration is checked based on <see cref="DateTime.UtcNow"/>.
        /// If expiration check must be skipped, use <see cref="Util.UtcMaxValue"/> as the expiration date.
        /// </para>
        /// </summary>
        /// <param name="data">The token.</param>
        /// <param name="checkExpirationDate">Optional check expiration date. Defaults to <see cref="DateTime.UtcNow"/>.</param>
        /// <returns>The information (possibly expired) or null if an error occurred.</returns>
        public FrontAuthenticationInfo? UnprotectFrontAuthenticationInfo( string data, DateTime? checkExpirationDate = null )
        {
            Throw.CheckNotNullArgument( data );
            var info = _frontTokenFormat.Unprotect( data )!;
            if( info == null ) return null;
            return info.SetInfo( info.Info.CheckExpiration( checkExpirationDate ?? DateTime.UtcNow ) );
        }

        /// <summary>
        /// Direct generation of an authentication token from any <see cref="IAuthenticationInfo"/>.
        /// <see cref="IAuthenticationInfo.CheckExpiration(DateTime)"/> is called with <see cref="DateTime.UtcNow"/>.
        /// <para>
        /// By default, the expiration is checked based on <see cref="DateTime.UtcNow"/>.
        /// If expiration check must be skipped, use <see cref="Util.UtcMaxValue"/> as the expiration date.
        /// </para>
        /// <para>
        /// This is to be used with caution: the authentication token should never be sent to any client and should be
        /// used only for secure server to server temporary authentication.
        /// </para>
        /// </summary>
        /// <param name="info">The authentication info for which an authentication token must be obtained.</param>
        /// <param name="checkExpirationDate">Optional check expiration date. Defaults to <see cref="DateTime.UtcNow"/>.</param>
        /// <returns>The url-safe secured authentication token string.</returns>
        public string UnsafeCreateAuthenticationToken( IAuthenticationInfo info, DateTime? checkExpirationDate = null )
        {
            Throw.CheckNotNullArgument( info );
            info = info.CheckExpiration( checkExpirationDate ?? DateTime.UtcNow );
            return ProtectFrontAuthenticationInfo( new FrontAuthenticationInfo( info, false ) );
        }

        /// <summary>
        /// Direct generation of an authentication token for a user.
        /// <para>
        /// This is to be used with caution: the authentication token should never be sent to any client and should be
        /// used only for secure server to server temporary authentication.
        /// </para>
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <param name="userName">The user name.</param>
        /// <param name="validity">The validity time span: the shorter the better.</param>
        /// <returns>The url-safe secured authentication token string.</returns>
        public string UnsafeCreateAuthenticationToken( int userId, string userName, TimeSpan validity )
        {
            var u = _typeSystem.UserInfo.Create( userId, userName );
            var info = _typeSystem.AuthenticationInfo.Create( u, DateTime.UtcNow.Add( validity ) );
            return ProtectFrontAuthenticationInfo( new FrontAuthenticationInfo( info, false ) );
        }

    }

}
