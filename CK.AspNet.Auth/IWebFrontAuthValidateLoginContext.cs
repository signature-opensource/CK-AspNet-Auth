using CK.Auth;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using System;
using System.Collections.Generic;
using System.Text;

namespace CK.AspNet.Auth
{
    /// <summary>
    /// Enables <see cref="IWebFrontAuthValidateLoginService.ValidateLoginAsync"/> to
    /// cancel login based on any criteria exposed by this context.
    /// </summary>
    public interface IWebFrontAuthValidateLoginContext
    {
        /// <summary>
        /// Gets the current http context.
        /// </summary>
        HttpContext HttpContext { get; }

        /// <summary>
        /// Gets the authentication type system.
        /// </summary>
        IAuthenticationTypeSystem AuthenticationTypeSystem { get; }

        /// <summary>
        /// Gets the endpoint that started the authentication.
        /// </summary>
        WebFrontAuthLoginMode LoginMode { get; }

        /// <summary>
        /// Gets the return url only if '/c/startLogin' has been called with a 'returnUrl' parameter.
        /// Null otherwise.
        /// </summary>
        string ReturnUrl { get; }

        /// <summary>
        /// Gets the authentication provider on which .webfront/c/starLogin has been called.
        /// This is "Basic" when <see cref="LoginMode"/> is <see cref="WebFrontAuthLoginMode.BasicLogin"/>. 
        /// </summary>
        string InitialScheme { get; }

        /// <summary>
        /// Gets the calling authentication scheme.
        /// This is usually the same as the <see cref="InitialScheme"/>.
        /// </summary>
        string CallingScheme { get; }

        /// <summary>
        /// Gets the current authentication when .webfront/c/starLogin has been called
        /// or the current authentication when <see cref="LoginMode"/> is <see cref="WebFrontAuthLoginMode.BasicLogin"/>
        /// or <see cref="WebFrontAuthLoginMode.UnsafeDirectLogin"/>.
        /// </summary>
        IAuthenticationInfo InitialAuthentication { get; }

        /// <summary>
        /// Gets the query parameters (for GET) or form data (when POST was used) of the 
        /// initial .webfront/c/starLogin call as a readonly list.
        /// </summary>
        IReadOnlyList<KeyValuePair<string, StringValues>> UserData { get; }

        /// <summary>
        /// Gets whether an error has already been set.
        /// </summary>
        bool HasError { get; }

        /// <summary>
        /// Cancels the login and sets an error message.
        /// The returned error contains the <paramref name="errorId"/>, the <see cref="InitialScheme"/>,
        /// <see cref="CallingScheme"/>, <see cref="UserData"/> and optionally the <paramref name="errorText"/>.
        /// Can be called multiple times: new error information replaces the previous one.
        /// </summary>
        /// <param name="errorId">Error identifier (a dotted identifier string). Can not be null or empty.</param>
        /// <param name="errorText">The error message in clear text.</param>
        void SetError( string errorId, string errorText );

        /// <summary>
        /// Cancels the login and sets an error message.
        /// The returned error has "errorId" set to the full name of the exception
        /// and the "errorText" is the <see cref="Exception.Message"/>.
        /// Can be called multiple times: new error information replaces the previous one.
        /// </summary>
        /// <param name="ex">The exception. Can not be null.</param>
        void SetError( Exception ex );
    }
}
