using CK.Auth;
using Microsoft.AspNetCore.Http;
#if NETSTANDARD1_6
using Microsoft.AspNetCore.Http.Authentication;
#else
using Microsoft.AspNetCore.Authentication;
#endif
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Diagnostics;
using CK.Core;

namespace CK.AspNet.Auth;

/// <summary>
/// Encapsulates the sign in data issued by an external provider.
/// </summary>
internal class WebFrontAuthLoginContext : IWebFrontAuthValidateLoginContext,
                                          IWebFrontAuthAutoCreateAccountContext,
                                          IWebFrontAuthAutoBindingAccountContext,
                                          IErrorContext
{
    readonly WebFrontAuthService _authenticationService;
    UserLoginResult? _failedLogin;
    internal UserLoginResult? _successfulLogin;
    internal string? _errorId;
    internal string? _errorText;
    // This contains the initial authentication but with the
    // requested "RememberMe" flag.
    readonly FrontAuthenticationInfo _initialAuth;
    // Used for Direct login (post return code).
    int _httpErrorCode;

    internal WebFrontAuthLoginContext( HttpContext ctx,
                                       WebFrontAuthService authService,
                                       IAuthenticationTypeSystem typeSystem,
                                       WebFrontAuthLoginMode loginMode,
                                       string callingScheme,
                                       object payload,
                                       AuthenticationProperties? authProps,
                                       string? initialScheme,
                                       FrontAuthenticationInfo initialAuth,
                                       bool impersonateActualUser,
                                       string? returnUrl,
                                       string? callerOrigin,
                                       IDictionary<string, string?> userData )
    {
        Debug.Assert( ctx != null && authService != null && typeSystem != null && !String.IsNullOrWhiteSpace( callingScheme ) && payload != null );
        HttpContext = ctx;
        _authenticationService = authService;
        AuthenticationTypeSystem = typeSystem;
        LoginMode = loginMode;
        CallingScheme = callingScheme;
        Payload = payload;

        _initialAuth = initialAuth;
        ImpersonateActualUser = impersonateActualUser;

        // CookieMode == None prevents any RememberMe.
        // And note that when CurrentOptions.UseLongTermCookie is false, we nevertheless allow the "RememberMe" functionality:
        // The cookie will be a non-session one (a regular cookie that will expire according to CurrentOptions.ExpireTimeSpan)
        // and as such, provides a "short term resiliency", a "remember me for the next {ExpireTimeSpan} even if I close my browser" functionality.
        RememberMe = initialAuth.RememberMe && authService.CookieMode != AuthenticationCookieMode.None;

        AuthenticationProperties = authProps;
        InitialScheme = initialScheme;
        ReturnUrl = returnUrl;
        CallerOrigin = callerOrigin;
        UserData = userData;
    }

    /// <summary>
    /// Gets the authentication type system.
    /// </summary>
    public IAuthenticationTypeSystem AuthenticationTypeSystem { get; }

    /// <summary>
    /// Gets the current http context.
    /// </summary>
    public HttpContext HttpContext { get; }

    /// <summary>
    /// Gets the endpoint that started the authentication.
    /// </summary>
    public WebFrontAuthLoginMode LoginMode { get; }

    /// <summary>
    /// Gets the Authentication properties.
    /// This is null when <see cref="LoginMode"/> is <see cref="WebFrontAuthLoginMode.BasicLogin"/>
    /// or <see cref="WebFrontAuthLoginMode.UnsafeDirectLogin"/>. 
    /// </summary>
    public AuthenticationProperties? AuthenticationProperties { get; }

    /// <summary>
    /// Gets the return url if '/c/startLogin' has been called with a 'returnUrl' parameter (the "inline login").
    /// </summary>
    public string? ReturnUrl { get; }

    /// <summary>
    /// Gets the caller scheme and host.
    /// Not null only if '/c/startLogin' has been called.
    /// </summary>
    public string? CallerOrigin { get; }

    /// <summary>
    /// Gets whether the login wants to keep the previous logged in user as the <see cref="IAuthenticationInfo.ActualUser"/>
    /// and becomes the <see cref="IAuthenticationInfo.User"/>.
    /// </summary>
    public bool ImpersonateActualUser { get; }

    /// <summary>
    /// Gets the authentication provider on which .webfront/c/starLogin has been called.
    /// This is "Basic" when <see cref="LoginMode"/> is <see cref="WebFrontAuthLoginMode.BasicLogin"/>
    /// and null when LoginMode is <see cref="WebFrontAuthLoginMode.None"/>. 
    /// </summary>
    public string? InitialScheme { get; }

    /// <summary>
    /// Gets the calling authentication scheme.
    /// This is usually the same as the <see cref="InitialScheme"/>.
    /// </summary>
    public string CallingScheme { get; }

    /// <summary>
    /// Gets whether the authentication should be memorized (or be as transient as possible).
    /// Note that this is always false when <see cref="AuthenticationCookieMode.None"/> is used.
    /// </summary>
    public bool RememberMe { get; }

    /// <summary>
    /// Gets the provider payload (type is provider dependent).
    /// This is never null but may be an empty object when unsafe login is used with no payload.
    /// </summary>
    public object Payload { get; }

    /// <summary>
    /// Gets the current authentication when .webfront/c/starLogin has been called
    /// or the current authentication when <see cref="LoginMode"/> is <see cref="WebFrontAuthLoginMode.BasicLogin"/>
    /// or <see cref="WebFrontAuthLoginMode.UnsafeDirectLogin"/>.
    /// </summary>
    public IAuthenticationInfo InitialAuthentication => _initialAuth.Info;

    /// <summary>
    /// Gets the user data that follows the process.
    /// </summary>
    public IDictionary<string, string?> UserData { get; }

    /// <summary>
    /// Gets whether SetError or SetSuccessfulLogin methods have been called.
    /// </summary>
    public bool IsHandled => _errorId != null || _successfulLogin != null;

    /// <summary>
    /// Gets whether an error has already been set.
    /// </summary>
    public bool HasError => _errorId != null;

    /// <summary>
    /// Sets an error message.
    /// The returned error contains the <paramref name="errorId"/> and <paramref name="errorText"/>,
    /// the <see cref="InitialScheme"/>, <see cref="CallingScheme"/> and <see cref="UserData"/>.
    /// Can be called multiple times: new error information replaces the previous one.
    /// </summary>
    /// <param name="errorId">Error identifier (a dotted identifier string). Must not be null or empty.</param>
    /// <param name="errorText">The optional error message in clear text (typically in english).</param>
    public void SetError( string errorId, string? errorText = null )
    {
        Throw.CheckNotNullOrWhiteSpaceArgument( errorId );
        _errorId = errorId;
        _errorText = errorText;
        _failedLogin = null;
    }

    UserLoginResult? IWebFrontAuthAutoCreateAccountContext.SetError( string errorId, string? errorText )
    {
        SetError( errorId, errorText );
        return null;
    }

    UserLoginResult? IWebFrontAuthAutoBindingAccountContext.SetError( string errorId, string? errorText )
    {
        SetError( errorId, errorText );
        return null;
    }

    /// <summary>
    /// Sets an error message.
    /// The returned error has "errorId" set to the full name of the exception
    /// and the "errorText" is the <see cref="Exception.Message"/>.
    /// Can be called multiple times: new error information replaces the previous one.
    /// </summary>
    /// <param name="ex">The exception.</param>
    public void SetError( Exception ex )
    {
        Throw.CheckNotNullArgument( ex );
        _errorId = ex.GetType().ToCSharpName();
        _errorText = ex.Message ?? "Exception has null message!";
        if( ex is ArgumentException ) _httpErrorCode = StatusCodes.Status400BadRequest;
        else _httpErrorCode = 0;
        _failedLogin = null;
    }

    UserLoginResult? IWebFrontAuthAutoCreateAccountContext.SetError( Exception ex )
    {
        SetError( ex );
        return null;
    }

    UserLoginResult? IWebFrontAuthAutoBindingAccountContext.SetError( Exception ex )
    {
        SetError( ex );
        return null;
    }

    /// <summary>
    /// Sets a login failure.
    /// The returned error contains the <see cref="InitialScheme"/>, <see cref="CallingScheme"/>, <see cref="UserData"/>,
    /// the "errorId" is "User.LoginFailure", the "errorMessage" is <see cref="UserLoginResult.LoginFailureReason"/>
    /// and a specific "loginFailureCode" contains the <see cref="UserLoginResult.LoginFailureCode"/>.
    /// Can be called multiple times: new error information replaces the previous one.
    /// </summary>
    /// <param name="loginFailed">Must be not null and <see cref="UserLoginResult.IsSuccess"/> must be false.</param>
    public void SetError( UserLoginResult loginFailed )
    {
        Throw.CheckArgument( loginFailed != null && !loginFailed.IsSuccess );
        _errorId = "User.LoginFailure";
        _errorText = loginFailed.LoginFailureReason;
        _failedLogin = loginFailed;
        Debug.Assert( _errorText != null );
    }

    /// <summary>
    /// Sets a successful login.
    /// Must be called only if <see cref="SetError(string, string)"/> or <see cref="SetError(UserLoginResult)"/>
    /// have not been called before.
    /// </summary>
    /// <param name="successResult">The result that must be successful.</param>
    public void SetSuccessfulLogin( UserLoginResult successResult )
    {
        if( successResult == null || !successResult.IsSuccess ) throw new ArgumentException( "Must be a login success.", nameof( successResult ) );
        if( _errorId != null ) throw new InvalidOperationException( $"An error ({_errorId}) has been already set." );
        _successfulLogin = successResult;
    }

    internal async Task SendResponseAsync( IActivityMonitor monitor )
    {
        if( !IsHandled ) throw new InvalidOperationException( "SetError or SetSuccessfulLogin must have been called." );
        if( _errorId != null )
        {
            if( LoginMode == WebFrontAuthLoginMode.UnsafeDirectLogin
                || LoginMode == WebFrontAuthLoginMode.BasicLogin )
            {
                await SendDirectAuthenticationErrorAsync();
                return;
            }
            await SendRemoteAuthenticationErrorAsync();
            return;
        }
        Debug.Assert( _successfulLogin != null );
        WebFrontAuthService.LoginResult r = await _authenticationService.HandleLoginAsync( HttpContext,
                                                                                           monitor,
                                                                                           _successfulLogin,
                                                                                           CallingScheme,
                                                                                           InitialAuthentication,
                                                                                           RememberMe,
                                                                                           ImpersonateActualUser );

        if( LoginMode == WebFrontAuthLoginMode.UnsafeDirectLogin
            || LoginMode == WebFrontAuthLoginMode.BasicLogin )
        {
            await SendDirectAuthenticationSuccessAsync( r );
            return;
        }
        await SendRemoteAuthenticationSuccessAsync( r );
    }

    Task SendDirectAuthenticationSuccessAsync( WebFrontAuthService.LoginResult r )
    {
        if( UserData != null ) r.Response.Add( UserData.ToJProperty() );
        return HttpContext.Response.WriteAsync( r.Response, StatusCodes.Status200OK );
    }

    Task SendDirectAuthenticationErrorAsync()
    {
        Debug.Assert( _errorId != null );
        int code = _httpErrorCode == 0 ? StatusCodes.Status401Unauthorized : _httpErrorCode;
        var newAuth = ImpersonateActualUser
                        ? _initialAuth
                        : _initialAuth.SetUnsafeLevel();

        JObject errObj = _authenticationService.CreateErrorAuthResponse( HttpContext, newAuth, _errorId, _errorText, InitialScheme, CallingScheme, UserData, _failedLogin );
        return HttpContext.Response.WriteAsync( errObj, code );
    }

    Task SendRemoteAuthenticationSuccessAsync( WebFrontAuthService.LoginResult r )
    {
        Debug.Assert( CallerOrigin != null, "/c/startLogin has been called." );
        if( ReturnUrl != null )
        {
            // "inline" mode.
            var caller = new Uri( CallerOrigin );
            var target = new Uri( caller, ReturnUrl );
            HttpContext.Response.Redirect( target.ToString() );
            return Task.CompletedTask;
        }
        // "popup" mode.
        var data = new JObject(
                        new JProperty( "initialScheme", InitialScheme ),
                        new JProperty( "callingScheme", CallingScheme ) );
        data.Add( UserData.ToJProperty() );
        r.Response.Merge( data );
        return HttpContext.Response.WriteWindowPostMessageAsync( r.Response, CallerOrigin );
    }

    Task SendRemoteAuthenticationErrorAsync()
    {
        Debug.Assert( _errorId != null && _errorText != null );
        return _authenticationService.SendRemoteAuthenticationErrorAsync(
                    HttpContext,
                    ImpersonateActualUser ? _initialAuth : _initialAuth.SetUnsafeLevel(),
                    ReturnUrl,
                    CallerOrigin,
                    _errorId,
                    _errorText,
                    InitialScheme,
                    CallingScheme,
                    UserData,
                    _failedLogin );
    }
}
