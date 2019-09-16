# Angular module for WebFrontAuth

Angular module and integration for WebFrontAuth (WFA) applications.

## Quick start

- `npm i @signature/ngx-webfrontauth`
- In the `imports` of your app module, add `NgxAuthModule.forRoot()`
- In your `main.ts`, **configure the module before bootstrap (see Requirements below)**
- Inject `AuthService` wherever you need it
- If you need route protection, use `AuthGuard` and/or `AuthSchemeGuard` in your routes

## Features

The following features are exposed:

- `AuthInterceptor`: An [`HttpInterceptor`](https://angular.io/guide/http#intercepting-requests-and-responses) using WFA authentication in calls.
- `AuthGuard`: An [Angular route guard](https://angular.io/guide/router#milestone-5-route-guards), returning `false` when the user is not authenticated with any scheme.
- `AuthSchemeGuard`: An [Angular route guard](https://angular.io/guide/router#milestone-5-route-guards), returning `false` when the user is, or is not, authenticated with specific authentication schemes.
- The WFA `AuthService` can be injected into your components, or services.

## Side effects

- `APP_INITIALIZER` is registered: WFA authentication is automatically refreshed on init.
- `HTTP_INTERCEPTORS` is registered: All requests made using the angular `HttpService` will be authenticated.

## Requirements

**Using NgxAuthModule requires you to inject configuration *before `bootstrapModule()` is called*, most likely in your `main.ts`:**

- `AuthServiceClientConfiguration`: The client configuration (URLs and login path)
- `AxiosInstance`: The `axios` instance to use when using WFA
- `IAuthenticationInfoTypeSystem`: The type system instance to use with WFA

A simple configuration looks like this:

```ts
import { AuthServiceClientConfiguration, createFactoryUsingCurrentHost } from './app/core/auth';
import { StdAuthenticationTypeSystem } from '@signature/webfrontauth/src/type-system';

platformBrowserDynamic([
  {
    provide: AuthServiceClientConfiguration,

    // If your WFA host is on the same machine and port (eg. using a SPA proxy):
    // Replace '/login' with the Angular route you use to log in.
    // This route automatically gets the 'returnUrl' query parameter.
    useFactory: createFactoryUsingCurrentHost('/login'),

    // If your WFA host is on another machine or port:
    // Create your own `AuthServiceClientConfiguration` here.
    //useValue: new AuthServiceClientConfiguration('/login', myEndpoint)
    deps: [],
  },
  {
    provide: 'AxiosInstance',
    useValue: axios.create(),
    deps: [],
  },
  {
    provide: 'IAuthenticationInfoTypeSystem',
    useValue: new StdAuthenticationTypeSystem(),
    deps: [],
  },
]).bootstrapModule(AppModule)
```
