import { enableProdMode } from '@angular/core';
import { platformBrowserDynamic } from '@angular/platform-browser-dynamic';

import { AppModule } from './app/app.module';
import { environment } from './environments/environment';
import axios from 'axios';
import { StdAuthenticationTypeSystem } from '@signature/webfrontauth/src/type-system';
import { AuthServiceClientConfiguration, createFactoryUsingCurrentHost } from 'projects/ngx-webfrontauth/src/public-api';

if (environment.production) {
  enableProdMode();
}

platformBrowserDynamic([
  {
    provide: AuthServiceClientConfiguration,
    useFactory: createFactoryUsingCurrentHost('/login'),
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
  .catch(err => console.error(err));
