# Angular module for WebFrontAuth

Angular module and integration for WebFrontAuth (WFA) applications.

## Quick start

- `npm i @signature/webfrontauth-ngx`
- In the `imports` of your app module, add `NgxAuthModule.forRoot()`
- In your `main.ts`, **configure the module before bootstrap (see Requirements below)**
- Inject `NgxAuthService` and/or `AuthService` wherever you need it
- If you need route protection, use `AuthGuard` and/or extend your own `AuthSchemeGuard` in your routes

## Features

The following features are exposed:

- `AuthInterceptor`: An [`HttpInterceptor`](https://angular.io/guide/http#intercepting-requests-and-responses) using WFA authentication in calls.
- `AuthGuard`: An [Angular route guard](https://angular.io/guide/router#milestone-5-route-guards) that blocks routes when the user is not authenticated, or is no longer safely authenticated.
- `AuthSchemeGuard`: An abstract class for an [Angular route guard](https://angular.io/guide/router#milestone-5-route-guards) that blocks routes depending on active authentication schemes.
- The WFA `AuthService` can be injected into your components, or services.
- `NgxAuthService`: A wrapper around `AuthService` that provides an `Observable<IUserInfo>` emitted every time authentication changes.

## Side effects

- `APP_INITIALIZER` is registered: WFA authentication is automatically refreshed on init.
- `HTTP_INTERCEPTORS` is registered: All requests made using the angular `HttpService` will be authenticated.

## Requirements

**Using NgxAuthModule requires you to inject configuration *before `bootstrapModule()` is called*, most likely in your `main.ts`,** by providing the following injection tokens:

- `AuthServiceClientConfiguration`: The client configuration (URLs and login path).
  - You can create your own, or use a helper function to use the current host (`createAuthConfigUsingCurrentHost`).
- `AXIOS`: The `axios` instance to use when using WFA.
  - This instance can be used throughout the rest of your application using `@Inject(AXIOS)` where appropriate.

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
