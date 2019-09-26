import { InjectionToken } from '@angular/core';
import { IAuthenticationInfoTypeSystem } from '@signature/webfrontauth/src/type-system';
import { IUserInfo } from '@signature/webfrontauth';
import { AxiosInstance } from 'axios';

export const WFA_TYPESYSTEM = new InjectionToken<IAuthenticationInfoTypeSystem<IUserInfo>>('IAuthenticationInfoTypeSystem<IUserInfo>');

export const AXIOS = new InjectionToken<AxiosInstance>('AxiosInstance');
