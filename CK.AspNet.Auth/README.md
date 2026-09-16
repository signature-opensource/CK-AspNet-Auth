# CK.AspNet.Auth

WebFrontAuth: an authentication scheme for a front-end application talking to its API. A bearer
token, optional cookies, expirations of very different natures, and a set of endpoints under one
entry path.

```csharp
builder.AddWebFrontAuth( o => o.ExpireTimeSpan = TimeSpan.FromMinutes( 30 ) );
// ...
var app = builder.CKBuild( map );   // UseAuthentication() is already appended for you
```

The order matters. `AddWebFrontAuth` registers services and appends `UseAuthentication()` to a
pipeline queue that `CKBuild` drains. Called after `CKBuild`, it does not fail quietly: `Build()`
has frozen the service collection and it throws *"The service collection cannot be modified
because it is read-only."* The one silent case is a *second* `AddWebFrontAuth` with no options
configurator: it touches nothing, whenever it is called.

The application must also supply an `IWebFrontAuthLoginService`. It is a required constructor
parameter of both `WebFrontAuthService` and the handler. Without it the application fails at
`CKBuild` in Development, where the container validates on build, and on the first request
otherwise. This package declares the contract and ships no implementation.

## Registration

[`AddWebFrontAuth`](WebFrontAuthExtensions.cs) registers three things and appends one. The
`WebFrontAuthService` singleton, a scoped `IAuthenticationInfo` resolved from the request's
`ScopedHttpContext`, and the scheme itself. Then it appends `UseAuthentication()` to the pipeline, so
you do not call it yourself.

It is idempotent, and calling it twice is a supported way to configure it. The second call does not
re-register anything. It adds another `IConfigureOptions<WebFrontAuthOptions>`, and every configurator
is applied to the final options. A package can call it to make sure it is there, and an application
can call it again to set its own values.

The scheme name is a constant, `"WebFrontAuth"`, because the service *"is not designed to be added
multiple times to an application, hence its name is unique."* That is about the scheme, not about the
registration call. The call also makes it the application's default authentication scheme.

The entry path is `/.webfront`.

## The endpoints

| Endpoint | Method | What it does |
|----------|--------|--------------|
| `/.webfront/c/refresh` | any | re-reads the authentication; always a fresh token, optionally extends `Expires` |
| `/.webfront/c/basicLogin` | POST | name and password, when the login service supports it |
| `/.webfront/c/startLogin` | any | starts an external provider flow |
| `/.webfront/c/unsafeDirectLogin` | POST | posts a scheme and its payload directly, with no provider round-trip - **403 unless explicitly enabled** |
| `/.webfront/c/logout` | any | clears the two cookies |
| `/.webfront/c/impersonate` | POST | impersonates, or clears an impersonation |
| `/.webfront/token` | any | returns the current authentication in clear |

An endpoint whose preconditions are not met is not there: everything under the path answers **404 by
default**, with no-cache. A POST-only endpoint reached with another verb answers 405, and `basicLogin`
is absent entirely when the login service has no basic login.

`/c/logout` clears the cookies and nothing else. The bearer token it was called with is still valid
afterwards, so a client that holds one drops it itself - which is what the test client does.

`/token` returns no token. It writes `{ info, rememberMe }`: the decoded `IAuthenticationInfo` in
clear. A token is what the logins, `/c/refresh` and `/c/impersonate` return.

The token endpoint sits beside `/c/`, not inside it. In the default cookie mode the authentication
cookie's path is `/.webfront/c/`, so `/token` is deliberately outside the cookie scope.

A login is a JSON POST:

```http
POST /.webfront/c/basicLogin HTTP/1.1
Host: localhost
Content-Type: application/json

{"userName":"Albert","password":"success"}
```

`/c/unsafeDirectLogin` matches its field names case-insensitively, explicitly. Do not generalise that:
`/c/impersonate` compares its key with an ordinal, case-sensitive test against `userName` or `userId`,
and the body must carry that one property and nothing else.

The body also accepts `rememberMe`, `impersonateActualUser`, and a `userData` object carried through
to the response. What comes back on success carries the authentication info, the token, the two flags
and whatever `userData` was posted:

```jsonc
// Illustration of the shape, not a captured response.
{
  "info": {
    "user": { /* id, name, schemes */ },
    "actualUser": { /* only when impersonated */ },
    "exp": "...",        // present when Expires has a value
    "cexp": "...",       // present when CriticalExpires has a value
    "device": "..."      // present when the device id is not empty
  },
  "token": "...",
  "refreshable": false,  // true only when SlidingExpirationTime is set
  "rememberMe": true,
  "userData": {}         // what the login posted, {} when it posted nothing
}
```

A direct-login failure - basic or unsafe direct - answers with that same shape plus `errorId`, and
`errorText` only when it is non-blank and different from `errorId`. The other failure paths do not:
an inline `/c/startLogin` error is a 400 carrying `errorId` and `errorText` alone, and a remote-login
failure with a `returnUrl` is a 302 whose parameters are in the query string. A direct-login failure
also carries `initialScheme` and `callingScheme` on both direct paths - `"Basic"` for `/c/basicLogin`,
the posted provider for `/c/unsafeDirectLogin` - plus `loginFailureCode` and `loginFailureReason`
whenever the refusal came with a `UserLoginResult`, which is the ordinary wrong-password case and also
a refusal from the auto-create or auto-binding service.
`userData` is on both the success and the failure, as an empty object when nothing was posted.
Malformed input does not get that far: an empty user name, an empty password or a body that is not
JSON all answer **400**, and the endpoint answers **404** when the login service has no basic login at
all.

## Expirations

`ExpireTimeSpan` defaults to **20 minutes** and governs the real authentication.

`UnsafeExpireTimeSpan` defaults to **366 days** and governs the unsafe one: the long-lived memory of
who this browser was. It is what lets a client survive an F5 without being authenticated.

`UseLongTermCookie` is derived rather than set. It is true when `UnsafeExpireTimeSpan` is non-null,
greater than `ExpireTimeSpan`, and cookies are not disabled. The long-term cookie is the auth cookie
name suffixed `LT`, and it is deliberately not `Secure`, *"since it does not require any protection"*:
it carries nothing that authenticates.

`SlidingExpirationTime` extends the first one. Its comment names only `/c/refresh`, but other paths do
it too: a successful `POST /c/impersonate`, `RefreshCommandAsync`, and, in `RootPath` cookie mode, any
request that resolves the authentication while the expiry is within half the sliding time.

The sliding touches `Expires` alone. `SetExpires` carries `CriticalExpires` through unchanged, so a
critical level cannot be kept alive by refreshing: it runs out on its own clock.

## Cookie modes

- `WebFrontPath` **(default)** - the cookie path is `/.webfront/c/`, so it is sent only to the
  authentication endpoints.

- `RootPath` - the standard ASP.NET cookie behaviour, so the cookie is sent on every request to the
  site. It is also the mode in which any request can slide the expiration: that sliding is gated on
  the mode itself, whatever the authentication was read from, so a bearer-only request slides too. The
  doc says it
  *"should NOT BE used in most cases: [...] is for standard and classical Web application."*

- `None` - no cookie at all, and it forces `UseLongTermCookie` off. It *"disables all cookies:
  client apps are no more "F5 resilient", this can be used for pure API implementations."*

## Options at runtime

These are re-read on every request, so changing one takes effect immediately:

- `ExpireTimeSpan`, `UnsafeExpireTimeSpan`, `UseLongTermCookie`
- `SlidingExpirationTime`, `AlwaysCallBackendOnRefresh`
- `AvailableSchemes`, `SchemesCriticalTimeSpan`, `UseFullClaimsPrincipalOnAuthenticate`

These are captured when `WebFrontAuthService` is constructed, so changing one requires restarting the
application:

- `CookieMode`, `CookieSecurePolicy`
- `AuthCookieName`, `BearerHeaderName`
- `AllowedReturnUrls`

What settles which list an option belongs to is not its own comment but whether that constructor
captures the value. `UseFullClaimsPrincipalOnAuthenticate` is in the first list despite its own
comment saying *"This cannot be changed dynamically"*: the handler reads it from its per-request
`Options` snapshot, and nothing captures it.

## Extension points

Nine interfaces under [`Extensions/`](Extensions): six optional services you implement, and three
context types. The contexts belong to the three services that get one - validate login, auto-create
and auto-binding. The dynamic scope provider is handed a `WebFrontAuthStartLoginContext`, a sealed
class declared outside that folder, and the impersonation service gets no WebFrontAuth context type
at all - just the `HttpContext`, the monitor, the current `IAuthenticationInfo` and the target user id
or name.

- [`IWebFrontAuthValidateLoginService`](Extensions/ValidateLogin/IWebFrontAuthValidateLoginService.cs) -
  cancel a login on any criterion. Where it runs, the login becomes three steps.

- [`IWebFrontAuthAutoCreateAccountService`](Extensions/AutoCreateAccount/IWebFrontAuthAutoCreateAccountService.cs) -
  create an account for a login whose user is not registered yet. Any mode, basic login included, not
  only an external provider. *"This should be used with care."*

- [`IWebFrontAuthAutoBindingAccountService`](Extensions/AutoBindingAccount/IWebFrontAuthAutoBindingAccountService.cs) -
  attach a new provider to the user already logged in. May treat a `Critical` level as sufficient
  proof.

- [`IWebFrontAuthImpersonationService`](Extensions/IWebFrontAuthImpersonationService.cs) - without it,
  `/c/impersonate` only supports impersonating back to the actual user, which is how an impersonation
  is cleared. It is also what implements `impersonateActualUser` on a login.

- [`IWebFrontAuthUnsafeDirectLoginAllowService`](Extensions/IWebFrontAuthUnsafeDirectLoginAllowService.cs) -
  the endpoint is `403 - Forbidden` until this exists. It is handed the scheme and the payload, and
  returns whether the call is allowed. *"Enabling calls to to this endpoint must be explicit"* - the
  stutter is in the source.

- [`IWebFrontAuthDynamicScopeProvider`](Extensions/IWebFrontAuthDynamicScopeProvider.cs) - the scopes
  to request from an external provider, per login. It is handed a `WebFrontAuthStartLoginContext`.

Implementing one is a class and a method - two methods for impersonation, which takes a user id or a
user name. The validator is the common case, and any error it sets cancels the login. Implicit usings
are off in this repository, so the four here are part of the example:

```csharp
using CK.AspNet.Auth;
using CK.Auth;
using CK.Core;
using System.Threading.Tasks;

public class BanCheck : IWebFrontAuthValidateLoginService
{
    public Task ValidateLoginAsync( IActivityMonitor monitor,
                                    IUserInfo loggedInUser,
                                    IWebFrontAuthValidateLoginContext context )
    {
        // Do Something, then refuse by setting an error:
        context.SetError( "User.Banned", "This account is suspended." );
        return Task.CompletedTask;
    }
}
```

It is an `IAutoService`, so the CKomposable engine finds it over the bin path: your assembly has to be
part of the generated `IStObjMap`. Registering it on the service collection works too, and is how the
tests of this repository supply the impersonation service and the unsafe-direct-login allower - no
test here registers a validator, and no implementation of one ships in the repository. Its presence
is asked first with `actualLogin` false, this method runs, and only if it sets no error is the login
service called again for real. It does not run on every login - a user created by the auto-create
service, or bound by the auto-binding one, reaches success without passing through it.
Impersonation carries its own rule, on the interface: *"Impersonation is not an actual login, it must
have no visible impact on the impersonated user data."*

## Secrets

The token and the authentication cookie go through
[`FrontAuthenticationInfoSecureDataFormat`](SecureData/FrontAuthenticationInfoSecureDataFormat.cs),
which protects them with the ASP.NET Data Protection API. The long-term cookie does not: it is written
as clear JSON, which is consistent with its carrying nothing that authenticates.

Key ring configuration is therefore an application concern: where keys live, how they are protected,
and whether they are shared across instances. Losing that ring costs every token and authentication
cookie already issued.

## Requirements

- `CK.AspNet`, for `ScopedHttpContext`, `AppendApplicationBuilder` and the request monitor.

- `CK.Auth.Abstractions`, for `IAuthenticationInfo`, `AuthLevel`, `IUserInfo` and
  `IAuthenticationTypeSystem`. The login service contract, `IWebFrontAuthLoginService`, is declared
  here rather than there.
