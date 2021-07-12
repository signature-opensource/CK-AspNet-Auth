# Angular module for WebFrontAuth

Angular module and integration for WebFrontAuth (WFA) applications.

## Quick start

- `npm i @signature/webfrontauth-ngx`
- In the `imports` array of your `AppModule`, add `NgxAuthModule.forRoot()`
- In the `providers` array of your `AppModule`, add `initializeAuthFactory` and/or `AuthInterceptor` (see *Example module* below)
- In your `main.ts`, **configure the module before bootstrap** *(see Requirements below)*
- Inject `NgxAuthService` and/or `AuthService` wherever you need it
- If you need route protection, use `AuthGuard` and/or extend your own `AuthSchemeGuard` in your routes

## Features

The following features are exposed:

- `AuthInterceptor`: An [`HttpInterceptor`](https://angular.io/guide/http#intercepting-requests-and-responses) using WFA authentication in calls.
- `AuthGuard`: An [Angular route guard](https://angular.io/guide/router#milestone-5-route-guards) that blocks routes when the user is not authenticated, or is no longer safely authenticated.
- `AuthSchemeGuard`: An abstract class for an [Angular route guard](https://angular.io/guide/router#milestone-5-route-guards) that blocks routes depending on active authentication schemes.
- `NgxAuthService`: A wrapper around `AuthService` that provides an `Observable<IAuthenticationInfo>` emitted every time authentication changes.
- The WFA `AuthService` can be injected into your components, or services.

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
    deps: [], // This is not required in latest angular versions.
    // If your WFA host is on the same machine and port (eg. using a SPA proxy):
    // Replace '/login' with the Angular route you use to log in.
    // This route automatically gets the 'returnUrl' query parameter.
    useValue: createAuthConfigUsingCurrentHost('/login')
    // If your WFA host is on another machine or port:
    // Create your own `AuthServiceClientConfiguration` here.
    useValue: new AuthServiceClientConfiguration(myEndpoint, '/login')
  },
  {
    provide: AXIOS,
    deps: [], // This is not required in latest angular versions.
    useValue: axios.create(),
  },
]).bootstrapModule(AppModule)
```

Optionally, you can also provide `WFA_TYPESYSTEM` to use your own `IAuthenticationInfoTypeSystem<IUserInfo>`.

## Example module

A simple `AppModule` using both `initializeAuthFactory` and `AuthInterceptor` looks like this:

```ts
import { HTTP_INTERCEPTORS } from '@angular/common/http';
import { APP_INITIALIZER, NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { AuthService } from '@signature/webfrontauth';
import { NgxAuthModule, AuthInterceptor, initializeAuthFactory } from '@signature/webfrontauth-ngx';
import { AppComponent } from './app.component';

@NgModule({
  declarations: [
    AppComponent
  ],
  imports: [
    BrowserModule,
    NgxAuthModule.forRoot()
  ],
  providers: [
    {
      // Refreshes authentication on startup
      provide: APP_INITIALIZER,
      useFactory: initializeAuthFactory,
      multi: true,
      deps: [AuthService]
    },
    {
      // Authenticates all HTTP requests made by Angular
      provide: HTTP_INTERCEPTORS,
      useClass: AuthInterceptor,
      multi: true
    }
  ],
  bootstrap: [AppComponent]
})
export class AppModule { }
```
