using System;
using System.Collections.Generic;
using System.Text;
using CK.Auth;

namespace CK.AspNet.Auth
{
    public class AccountBindingResult
    {
        public AccountBindingResult( IUserInfo info, int failureCode, string failureReason )
        {
            if( info == null || info.UserId == 0 )
            {
                if( failureReason == null )
                {
                    throw new ArgumentException( $"Null or anonymous: failure reason must be not null.", nameof( failureReason ) );
                }
                if( failureCode <= 0 )
                {
                    throw new ArgumentException( $"Null or anonymous: failure code must be positive (value: {failureCode}).", nameof( failureCode ) );
                }
                BindingFailureCode = failureCode;
                BindingFailureReason = failureReason;
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
                UserInfo = info;
            }
        }

        /// <summary>
        /// Gets the user information.
        /// Null if for any reason, binding failed.
        /// </summary>
        public IUserInfo UserInfo { get; }

        /// <summary>
        /// Gets whether the binding succeeded.
        /// </summary>
        public bool IsSuccess => UserInfo != null;

        /// <summary>
        /// Gets the binding failure code.
        /// This value is positive if binding failed.
        /// </summary>
        public int BindingFailureCode { get; }

        /// <summary>
        /// Gets a string describing the reason of a binding failure.
        /// Null on success.
        /// </summary>
        public string BindingFailureReason { get; }
    }
}
