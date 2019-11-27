import { IResponseInfo, IWebFrontAuthResponse, IResponseUserInfo } from "../../src/index.private";

interface ILoginFailure {
    loginFailureCode: number;
    loginFailureReason: string;
}

interface IError {
    errorId: string;
    errorText: string;
}

export default class ResponseBuilder {

    private _info: IResponseInfo = null;
    private _token: string = null;
    private _refreshable: boolean = null;
    private _error: IError = null;
    private _schemes: string[] = null;
    private _loginFailure: ILoginFailure = null;
    private _version: string = null;

    public withInfo(info: IResponseInfo): ResponseBuilder {
        this._info = info;
        return this;
    }

    public withUser(user: IResponseUserInfo): ResponseBuilder {
        if( !this._info ) {
            this._info = { user };
        } else {
            this._info.user = user;
        }
        return this;
    }

    public withActualUser(actualUser: IResponseUserInfo): ResponseBuilder {
        if( !this._info) {
            throw new Error('An user must be defined.');
        }

        this._info.actualUser = actualUser;
        return this;
    }

    public withExpires(exp: Date): ResponseBuilder {
        if (!this._info) {
            throw new Error('An user must be defined.');
        }

        this._info.exp = exp;
        return this;
    }

    public withCriticalExpires(cexp: Date): ResponseBuilder {
        if (!this._info) {
            throw new Error('An user must be defined.');
        }

        this._info.cexp = cexp;
        return this;
    }

    public withToken(token: string): ResponseBuilder {
        this._token = token;
        return this;
    }

    public withRefreshable(refreshable: boolean): ResponseBuilder {
        this._refreshable = refreshable;
        return this;
    }

    public withError(error: IError): ResponseBuilder {
        if (this._loginFailure) {
            throw new Error('Both error and login should not exist at the same time.');
        }

        this._error = error;
        return this;
    }

    public withLoginFailure(loginFailure: ILoginFailure): ResponseBuilder {
        if (this._error) {
            throw new Error('Both error and login should not exist at the same time.');
        }

        this._loginFailure = loginFailure;
        return this;
    }

    public withVersion(version: string): ResponseBuilder {
        this._version = version;
        return this;
    }

    public withSchemes(schemes: string[]): ResponseBuilder {
        this._schemes = schemes;
        return this;
    }

    public build(): IWebFrontAuthResponse {
        const response: IWebFrontAuthResponse = {
            info: this._info,
            token: this._token,
            refreshable: this._refreshable
        };

        if (this._loginFailure) {
            response.loginFailureCode = this._loginFailure.loginFailureCode;
            response.loginFailureReason = this._loginFailure.loginFailureReason;
        }

        if (this._error) {
            response.errorId = this._error.errorId;
            response.errorText = this._error.errorText;
        }

        if (this._version) {
            response.version = this._version;
        }

        if (this._schemes) {
            response.schemes = this._schemes;
        }

        return response;
    }
}
