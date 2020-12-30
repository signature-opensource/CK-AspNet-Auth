using CK.Auth;
using System;
using System.Collections.Generic;
using System.Text;

namespace CK.AspNet.Auth
{
    /// <summary>
    /// Encapsulates login result information.
    /// </summary>
    public class UserLoginResult
    {
        /// <summary>
        /// Initializes a new login result.
        /// </summary>
        /// <param name="info">The user info. When null or anonymous, failure code and reason must indicate an error.</param>
        /// <param name="failureCode">
        /// Failure code must be positive on failure, zero on success.
        /// Standard <see cref="IWebFrontAuthLoginService"/> implementation by CK.DB.AspNetAuth (the SqlWebFrontAuthLoginService class) uses
        /// the CK.DB.Auth.KnownLoginFailureCode that is defined here: https://github.com/Invenietis/CK-DB/blob/develop/CK.DB.Auth/KnownLoginFailureCode.cs.
        /// </param>
        /// <param name="failureReason">Failure reason must be not null on failure, null on success.</param>
        /// <param name="unregisteredUser">
        /// Indicates that the login failed because the user is not registered in the provider: this may be
        /// corrected by registering the user for the provider.
        /// This can be true only on failure otherwise an argument exception is thrown.
        /// </param>
        public UserLoginResult( IUserInfo info, int failureCode, string failureReason, bool unregisteredUser )
        {
            if( info == null || info.UserId == 0 )
            {
                if( failureReason == null )
                {
                    throw new ArgumentException( $"Null or anonymous: failure reason must be not null.", nameof(failureReason) );
                }
                if( failureCode <= 0 )
                {
                    throw new ArgumentException( $"Null or anonymous: failure code must be positive (value: {failureCode}).", nameof(failureCode) );
                }
                LoginFailureCode = failureCode;
                LoginFailureReason = failureReason;
                IsUnregisteredUser = unregisteredUser;
            }
            else
            {
                if( failureReason != null )
                {
                    throw new ArgumentException( $"Valid user info: failure reason must be null (value: {failureReason}).", nameof( failureReason ) );
                }
                if( failureCode != 0 )
                {
                    throw new ArgumentException( $"Valid user info: : failure code must be zero (value: {failureCode}).", nameof( failureCode ) );
                }
                if( unregisteredUser )
                {
                    throw new ArgumentException( $"Valid user info: it can not be an unregistered user.", nameof( unregisteredUser ) );
                }
                UserInfo = info;
            }
        }

        /// <summary>
        /// Gets the user information.
        /// Null if for any reason, login failed.
        /// </summary>
        public IUserInfo? UserInfo { get; }

        /// <summary>
        /// Gets whether the login succeeded.
        /// </summary>
        public bool IsSuccess => UserInfo != null;

        /// <summary>
        /// Gets whether the failure may be corrected by registering the user
        /// for the provider.
        /// </summary>
        public bool IsUnregisteredUser { get; }

        /// <summary>
        /// Gets the login failure code. This value is positive if login failed. 
        /// Standard <see cref="IWebFrontAuthLoginService"/> implementation by CK.DB.AspNetAuth (the SqlWebFrontAuthLoginService class) uses
        /// the CK.DB.Auth.KnownLoginFailureCode that is defined here: https://github.com/Invenietis/CK-DB/blob/develop/CK.DB.Auth/KnownLoginFailureCode.cs.
        /// </summary>
        public int LoginFailureCode { get; }

        /// <summary>
        /// Gets a string describing the reason of a login failure.
        /// Null on success.
        /// </summary>
        public string? LoginFailureReason { get; }
    }
}
