/**
 * This models the server response.
 */
export interface  IWebFrontAuthResponse {
    info?: IResponseInfo;
    token?: string;
    rememberMe?: boolean;
    refreshable?: boolean;
    schemes?: string[];
    loginFailureCode?: number;
    loginFailureReason?: string;
    errorId?: string;
    errorText?: string;
    initialScheme?: string;
    callingScheme?: string;
    userData?: any;
    version?: string;
}

export interface IResponseInfo {
    user: IResponseUserInfo;
    actualUser?: IResponseUserInfo;
    exp?: Date;
    cexp?: Date;
    deviceId: string;
}

export interface IResponseUserInfo {
    id: number;
    name: string;
    schemes: IResponseScheme[];
}

export interface IResponseScheme {
    name: string;
    lastUsed: Date;
}
