import { IWebFrontAuthError, IResponseError, ILoginError } from "./authService.model.public";

export class WebFrontAuthError implements IWebFrontAuthError {
    public readonly type: string;
    public readonly errorId: string;
    public readonly errorReason: string;

    constructor(public readonly error: IResponseError | ILoginError) {
        if (this.isErrorType<IResponseError>(error)) {
            this.type = "Protocol";
            this.errorId = error.errorId;
            this.errorReason = error.errorReason;
        } else if (this.isErrorType<ILoginError>(error)) {
            this.type = "Login";
            this.errorId = error.loginFailureCode.toString();
            this.errorReason = error.loginFailureReason;
        } else {
            throw new Error(`Invalid argument: error ${error}`);
        }
    }

    protected isErrorType<T extends IResponseError | ILoginError>(error: IResponseError | ILoginError): error is T {
        return !!(error as T);
    }

}

