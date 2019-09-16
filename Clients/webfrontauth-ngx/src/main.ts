import { enableProdMode } from '@angular/core';
import { platformBrowserDynamic } from '@angular/platform-browser-dynamic';

import { AppModule } from './app/app.module';
import { environment } from './environments/environment';
import axios from 'axios';
import { AuthServiceClientConfiguration, createAuthConfigUsingCurrentHost } from 'projects/webfrontauth-ngx/src/public-api';

if (environment.production) {
  enableProdMode();
}

platformBrowserDynamic([
  {
    provide: AuthServiceClientConfiguration,
    useValue: createAuthConfigUsingCurrentHost('/login'),
    deps: [],
  },
  {
    provide: 'AxiosInstance',
    useValue: axios.create(),
    deps: [],
  },
]).bootstrapModule(AppModule)
  .catch(err => console.error(err));
