# Angular module for WebFrontAuth

Angular module and integration for WebFrontAuth (WFA) applications.

## Quick start

- `npm i @signature/webfrontauth-ngx`
- In the `imports` array of your `AppModule`, add `NgxAuthModule.forRoot()`
- In your `main.ts`, **configure the module before bootstrap (see Requirements below)**
- Inject `NgxAuthService` and/or `AuthService` wherever you need it
- If you need route protection, use `AuthGuard` and/or extend your own `AuthSchemeGuard` in your routes

## Features

The following features are exposed:

- `AuthInterceptor`: An [`HttpInterceptor`](https://angular.io/guide/http#intercepting-requests-and-responses) using WFA authentication in calls.
- `AuthGuard`: An [Angular route guard](https://angular.io/guide/router#milestone-5-route-guards) that blocks routes when the user is not authenticated, or is no longer safely authenticated.
- `AuthSchemeGuard`: An abstract class for an [Angular route guard](https://angular.io/guide/router#milestone-5-route-guards) that blocks routes depending on active authentication schemes.
- `NgxAuthService`: A wrapper around `AuthService` that provides an `Observable<IAuthenticationInfo>` emitted every time authentication changes.
- The WFA `AuthService` can be injected into your components, or services.

## Side effects

`@signature/webfrontauth-ngx` provides `HTTP_INTERCEPTORS` and `APP_INITIALIZER`, which may affect your entire application:

- With `APP_INITIALIZER`: WFA authentication is automatically refreshed on init.
  - **This may cause your application to fail on init if if the WFA endpoint fails to respond.**
- With `HTTP_INTERCEPTORS`: All requests made using the Angular `HttpService` will be authenticated by injecting the user token from `AuthService` into the `Authorization: Bearer` HTTP request header.
  - **No domain check is made.** Ensure your application does *not* call third party or untrusted domains with the Angular `HttpService`, or **your user token will leak to the outside.**

You can prevent the module from injecting automatic providers by calling `NgxAuthModule.forRoot( false )` *instead of*  `NgxAuthModule.forRoot()` in your `AppModule`.

## Requirements

**Using NgxAuthModule requires you to inject configuration *before `bootstrapModule()` is called*, most likely in your `main.ts`,** by providing the following injection tokens:

- `AuthServiceClientConfiguration`: The client configuration (URLs and login path).
  - You can create your own, or use a helper function to use the current host (`createAuthConfigUsingCurrentHost`).
- `AXIOS`: The `axios` instance that should be used by WFA.
  - This instance can be used throughout the rest of your application by using `@Inject(AXIOS)` where appropriate.
  - This instance will be authenticated by WFA. The security notes from `HttpService` also apply here (see `Side effects` above).

A simple configuration looks like this:

```ts
import axios from 'axios';
import { AXIOS, AuthServiceClientConfiguration, createAuthConfigUsingCurrentHost } from '@signature/webfrontauth-ngx';

platformBrowserDynamic([
  {
    provide: AuthServiceClientConfiguration,
    deps: [],

    // If your WFA host is on the same machine and port (eg. using a SPA proxy):
    // Replace '/login' with the Angular route you use to log in.
    // This route automatically gets the 'returnUrl' query parameter.
    useValue: createAuthConfigUsingCurrentHost('/login'),

    // If your WFA host is on another machine or port:
    // Create your own `AuthServiceClientConfiguration` here.
    //useValue: new AuthServiceClientConfiguration(myEndpoint, '/login')
  },
  {
    provide: AXIOS,
    deps: [],
    useValue: axios.create(),
  },
]).bootstrapModule(AppModule)
```

Optionally, you can also provide `WFA_TYPESYSTEM` to use your own `IAuthenticationInfoTypeSystem<IUserInfo>`.
