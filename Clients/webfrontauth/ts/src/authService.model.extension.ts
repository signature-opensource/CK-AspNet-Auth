import { IWebFrontAuthError, IResponseError, ILoginError } from "./authService.model.public";

export class WebFrontAuthError implements IWebFrontAuthError {
    public readonly type: string;
    public readonly errorId: string;
    public readonly errorText: string;

    constructor(public readonly error: IResponseError | ILoginError) {
        if (this.isResponseError(error)) {
            this.type = "Protocol";
            this.errorId = error.errorId;
            this.errorText = error.errorText;
        } else if (this.isLoginError(error)) {
            this.type = "Login";
            this.errorId = error.loginFailureCode.toString();
            this.errorText = error.loginFailureReason;
        } else {
            throw new Error(`Invalid argument: error ${error}`);
        }
    }

    protected isResponseError(error: IResponseError | ILoginError): error is IResponseError {
        const cast = (error as IResponseError);
        return !!cast.errorId || !!cast.errorText;
    }

    protected isLoginError(error: IResponseError | ILoginError): error is ILoginError {
        const cast = (error as ILoginError);
        return !!cast.loginFailureCode && !!cast.loginFailureReason;
    }
}

