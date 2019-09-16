import { Injectable } from '@angular/core';
import { HttpInterceptor, HttpEvent, HttpHandler, HttpRequest } from '@angular/common/http';
import { Observable } from 'rxjs';
import { AuthService } from '@signature/webfrontauth';

@Injectable({ providedIn: 'root' })
export class AuthInterceptor implements HttpInterceptor {

    constructor(
        private authService: AuthService
    ) {
    }

    public intercept(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
        return next.handle(
            this.authService.token !== ''
                ? request.clone({headers: request.headers.set('Authorization', 'Bearer ' + this.authService.token)})
                : request
        );
    }
}
