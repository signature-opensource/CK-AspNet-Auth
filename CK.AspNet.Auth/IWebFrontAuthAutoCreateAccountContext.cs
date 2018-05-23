using CK.Auth;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using System;
using System.Collections.Generic;
using System.Text;

namespace CK.AspNet.Auth
{
    /// <summary>
    /// Enables <see cref="IWebFrontAuthAutoCreateAccountService.CreateAccountAndLoginAsync"/> to
    /// attempt to create an account and log in the user based on any criteria exposed by this context.
    /// </summary>
    public interface IWebFrontAuthAutoCreateAccountContext
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
        /// Gets the provider payload (type is provider -ie. <see cref="CallingScheme"/>- dependent).
        /// This is never null but may be an empty object when unsafe login is used with no payload.
        /// </summary>
        object Payload { get; }

        /// <summary>
        /// Gets the query parameters (for GET) or form data (when POST was used) of the 
        /// initial .webfront/c/starLogin call as a readonly list.
        /// </summary>
        IReadOnlyList<KeyValuePair<string, StringValues>> UserData { get; }

    }
}
