# CK.Testing.AspNetServer.Auth

One helper that starts a real server with WebFrontAuth already wired, plus a fake user database with
five named users, so a test can log in on the first line instead of building an identity stack.

> ℹ️ Read [CK.AspNet.Auth](../CK.AspNet.Auth/README.md) for the scheme itself. This package makes it
> startable in a test and fills in what a real application would provide.

## The entry point

```csharp
public static Task<RunningAspNetServer> CreateRunningAspNetAuthenticationServerAsync(
        this WebApplicationBuilder builder,
        IStObjMap map,
        Action<WebFrontAuthOptions>? authOptions = null,
        Action<WebApplication>? configureApplication = null )
```

What it substitutes depends on what the map already has, so it works on a real map as well as an
empty one. If the `IStObjMap` has no `IWebFrontAuthLoginService`,
[`FakeWebFrontAuthLoginService`](FakeWebFrontAuthLoginService.cs) is registered. If it has no
`IUserInfoProvider`, [`FakeUserDatabase`](FakeUserDatabase.cs) is. An application that brings its own
keeps its own.

Two traps come with that. The login-service branch registers `FakeUserDatabase` too, because
`FakeWebFrontAuthLoginService` takes the concrete type. Supply an `IUserInfoProvider` but no login
service, and the fake logs against that fake database rather than against your provider. And when
both branches fire - the ordinary empty-map case - the two `TryAddSingleton` calls are two
descriptors, so the `IUserInfoProvider` the application resolves and the `FakeUserDatabase` the login
service holds are two different instances. Mutate the concrete one; the tests of `CK.AspNet.Auth`
avoid the split by forwarding `IUserInfoProvider` to it.

It also calls `AddUnsafeAllowAllCors`, which allows every origin, method and header with credentials.
The name is the warning, and the extension's own doc repeats it: *"This is unfortunately required in
some testing scenario but should NEVER be used in production."*

The helper takes an `IStObjMap`, so a test that has no generated map cannot use it.

## Logging in

One call on the client, and the password defaults to `"success"`:

```csharp
await using var runningServer = await builder.CreateRunningAspNetAuthenticationServerAsync( map );

var login = await runningServer.Client.AuthenticationBasicLoginAsync( "Albert", expectSuccess: true );
```

`rememberMe` defaults to true, so the body it posts to `/.webfront/c/basicLogin` is
`{"userName":"Albert", "password":"success", "rememberMe":true}`. That is not cosmetic: it drives
what the long-term cookie carries, and the helper asserts it. The response is parsed into an
`AuthServerResponse`, `Client.Token` is set, and the cookies are checked on both paths. Only the
status, the level and the actual user name are gated by `expectSuccess`. Its siblings on the same
client are `AuthenticationRefreshAsync`, `AuthenticationLogoutAsync`,
`AuthenticationImpersonateAsync` and `AuthenticationReadCookies`.

## The fake users

[`FakeUserDatabase`](FakeUserDatabase.cs) contains five users:

| User | Id | Providers |
|------|----|-----------|
| `System` | 1 | none |
| `Alice` | 3711 | `Basic` |
| `Albert` | 3712 | `Basic` |
| `Robert` | 3713 | none |
| `Hubert` | 3714 | `Basic`, `Google` |

[`FakeWebFrontAuthLoginService`](FakeWebFrontAuthLoginService.cs) implements `Basic` only, and the
password is `"success"` for every existing user - including `Robert` and `System`, who have no
provider at all. Do not use them as the "user without the scheme" fixture; they are not one.

Its remarks claim the login succeeds only for a user registered in the `Basic` provider. What the
scheme check really gates is the rewrite of the user's entry - a fresh `LastUsed`, and a scheme list
reduced to the single `Basic` entry just used. The success is returned past it.

So logging `Hubert` in costs him his `Google` scheme for the rest of the test, while `Robert` and
`System` log in with their entry untouched.

An unknown user name with the right password is worse than a failure. The service builds a
`UserLoginResult` with a null user and no failure reason, which the result type refuses: it throws.
You get a caught exception rather than a clean login failure.

Both types are built to be bent. `AllUsers` is *"totally mutable and everything is virtual"*, and the
login service *"can be totally specialized"*. Add a user mid-test, or derive and refuse one.

The pairing carries a caveat, stated where the two are wired together. `IUserInfoProvider` and
`IWebFrontAuthLoginService` are separate interfaces by the interface-segregation principle, but
*"implementations should be coherent. This cannot be challenged here (and in a way it shouldn't
be)."* Substitute one and you own keeping it consistent with the other.

That paragraph is loose `///` text outside any XML element, between the `</summary>` and an empty
`<remarks>`.

## Reading the response

[`AuthServerResponse.Parse`](AuthServerResponse.cs) turns a login, refresh, impersonate or `/token`
answer into an object:

- `Info` - the `IAuthenticationInfo`, and `Token`.
- `RememberMe` and `Refreshable`.
- `ErrorId` and `ErrorText`, the failure pair.
- `Schemes`, `Version`, and the `UserData` the login carried.

[`AuthenticationCookieValues`](AuthenticationCookieValues.cs) captures the cookie side instead: the
auth cookie, the long-term cookie, and the device, user id and user name read out of it. That is how a
test asserts on what survives an expiry rather than on what the last response said.

## Requirements

- `CK.AspNet.Auth`, the scheme being started.

- `CK.Testing.AspNetServer`, for `RunningAspNetServer` and the client.
