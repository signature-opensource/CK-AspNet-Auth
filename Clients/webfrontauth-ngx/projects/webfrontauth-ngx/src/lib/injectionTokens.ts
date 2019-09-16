import { InjectionToken } from '@angular/core';
import { IAuthenticationInfoTypeSystem } from '@signature/webfrontauth/src/type-system';
import { IUserInfo } from '@signature/webfrontauth';
import { AxiosInstance } from 'axios';

export const WFA_TYPESYSTEM: InjectionToken<IAuthenticationInfoTypeSystem<IUserInfo>>
= new InjectionToken<IAuthenticationInfoTypeSystem<IUserInfo>>('IAuthenticationInfoTypeSystem<IUserInfo>');

export const AXIOS: InjectionToken<AxiosInstance>
= new InjectionToken<AxiosInstance>('AxiosInstance');
