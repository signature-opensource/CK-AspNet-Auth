export interface IWebFrontAuthResponse {
    info: {
        user: IResponseUserInfo;
        actualUser: IResponseUserInfo;
        exp: Date;
        cexp: Date;
    };
    token: string;
    refreshable: boolean;
    schemes: string[];
    loginFailureCode: number;
    loginFailureReason: string;
    errorId: string;
    errorText: string;
    initialScheme: string;
    callingScheme: string;
    userData: any;
    version: string;
}

export interface IResponseUserInfo {
    id: number;
    name: string;
    schemes: IResponseScheme[];
}

export interface IResponseScheme {
    name: string;
    lastUsed: string;
}