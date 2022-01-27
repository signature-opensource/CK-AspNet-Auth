using System;
using System.Collections.Generic;
using System.Text;
using CK.Auth;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;

namespace CK.AspNet.Auth
{
    /// <summary>
    /// Enables <see cref="IWebFrontAuthAutoBindingAccountService.BindAccountAsync"/> to
    /// attempt to bind an account to a currently already logged in user.
    /// </summary>
    public interface IWebFrontAuthAutoBindingAccountContext
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
        /// <para>
        /// This url is always checked against the <see cref="WebFrontAuthOptions.AllowedReturnUrls"/> set of allowed prefixes. 
        /// </para>
        /// </summary>
        string? ReturnUrl { get; }

        /// <summary>
        /// Gets the authentication provider on which .webfront/c/starLogin has been called.
        /// This is "Basic" when <see cref="LoginMode"/> is <see cref="WebFrontAuthLoginMode.BasicLogin"/>
        /// and null when LoginMode is <see cref="WebFrontAuthLoginMode.None"/>. 
        /// </summary>
        string? InitialScheme { get; }

        /// <summary>
        /// Gets the calling authentication scheme.
        /// This is usually the same as the <see cref="InitialScheme"/>.
        /// </summary>
        string CallingScheme { get; }

        /// <summary>
        /// Gets the provider payload (type is provider -ie. <see cref="CallingScheme"/>- dependent).
        /// This is never null but may be an empty object when unsafe login is used with no payload.
        /// </summary>
        object Payload { get; }

        /// <summary>
        /// Gets the query parameters (for GET) or form data (when POST was used) of the 
        /// initial .webfront/c/starLogin call as a readonly list.
        /// </summary>
        IReadOnlyList<KeyValuePair<string, StringValues>> UserData { get; }

        /// <summary>
        /// Gets the authentication information of the current authentication.
        /// </summary>
        IAuthenticationInfo InitialAuthentication { get; }

        /// <summary>
        /// Sets an error and always returns null to easily return
        /// from <see cref="IWebFrontAuthAutoBindingAccountService.BindAccountAsync"/> method.
        /// </summary>
        /// <param name="errorId">Error identifier (a dotted identifier string). Must not be null or empty.</param>
        /// <param name="errorText">The optional error message in clear text (typically in english).</param>
        /// <returns>Always null.</returns>
        UserLoginResult? SetError( string errorId, string? errorText = null );

        /// <summary>
        /// Sets an error and always returns null to easily return
        /// from <see cref="IWebFrontAuthAutoBindingAccountService.BindAccountAsync"/> method.
        /// The returned error has "errorId" set to the full name of the exception
        /// and the "errorText" is the <see cref="Exception.Message"/>.
        /// Can be called multiple times: new error information replaces the previous one.
        /// </summary>
        /// <param name="ex">The exception. Can not be null.</param>
        /// <returns>Always null.</returns>
        UserLoginResult? SetError( Exception ex );
    }
}
