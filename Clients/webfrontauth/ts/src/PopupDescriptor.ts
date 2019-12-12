
export type Collector = (s:string) => void;

/**
 * Mutable description of the basic popup window (it has to be a real browser's 'window).
 */
export class PopupDescriptor {

    private _popupTitle: string = 'Connection';
    public get popupTitle(): string { return this._popupTitle; }
    public set popupTitle( popupTitle: string ) { if( popupTitle ) { this._popupTitle = popupTitle; } }

    private _features: string = 'menubar=no, status=no, scrollbars=no, menubar=no, width=700, height=700';
    public get features(): string { return this._features; }
    public set features( features: string ) { if( features ) { this._features = features; } }

    private _basicFormTitle: string = 'Connection';
    public get basicFormTitle(): string { return this._basicFormTitle; }
    public set basicFormTitle( basicFormTitile: string ) { if( basicFormTitile ) { this._basicFormTitle = basicFormTitile; } }

    private _basicUserNamePlaceholder: string = 'username';
    public get basicUserNamePlaceholder(): string { return this._basicUserNamePlaceholder; }
    public set basicUserNamePlaceholder( basicUserNamePlaceholder: string ) {
        if( basicUserNamePlaceholder ) { this._basicUserNamePlaceholder = basicUserNamePlaceholder; }
    }

    private _basicPasswordPlaceholder: string = 'password';
    public get basicPasswordPlaceholder(): string { return this._basicPasswordPlaceholder; }
    public set basicPasswordPlaceholder( baiscPasswordPlaceholder: string ) {
        if( baiscPasswordPlaceholder ) { this._basicPasswordPlaceholder = baiscPasswordPlaceholder; }
    }

    private _basicSubmitButtonLabel: string = 'Submit';
    public get basicSubmitButtonLabel(): string { return this._basicSubmitButtonLabel; }
    public set basicSubmitButtonLabel( basicSubmitButtonLabel: string ) {
        if( basicSubmitButtonLabel ) { this._basicSubmitButtonLabel = basicSubmitButtonLabel; }
    }

    private _basicMissingCredentialsError: string = 'Missing credentials.';
    public get basicMissingCredentialsError() : string { return this._basicMissingCredentialsError; }
    public set basicMissingCredentialsError( basicMissingCredentialsError: string ) { 
        if( basicMissingCredentialsError ) { this._basicMissingCredentialsError = basicMissingCredentialsError; }
    }
    private _basicInvalidCredentialsError: string = 'Invalid credentials.';
    public get basicInvalidCredentialsError(): string { return this._basicInvalidCredentialsError; }
    public set basicInvalidCredentialsError( basicInvalidCredentialsError: string ) {
        if( basicInvalidCredentialsError ) { this._basicInvalidCredentialsError = basicInvalidCredentialsError; }
    }

    public generateBasicHtml(): string {
        const buffer: string[] = [];

        buffer.push( '<!DOCTYPE html> <html>' );
        this.generateHeader( (s: string) => buffer.push( s ) );
        this.generateBody( (s: string) => buffer.push( s ) );
        buffer.push( '</html>' );

        return buffer.join( ' ' );
    }
    
    protected generateHeader( collector: Collector ): void {
        collector('<head> <title>');
        collector( this.popupTitle );
        collector( '</title>' );
        this.generateStyle( collector );
        collector('</head>');
    }

    protected generateStyle( collector: Collector ): void {
        collector( '<style>' );
        collector(
`body{
font-family: Avenir,Helvetica,Arial,sans-serif;
-webkit-font-smoothing: antialiased;
-moz-osx-font-smoothing: grayscale;
text-align: center;
color: #2c3e50;
margin-top: 60px;
}
h1{
font-weight: 400;
}
.error{
margin: auto auto 10px;
width: 40%;
background-color: rgb(239, 181, 181);
border-radius: 5px;
padding: 3px;
font-size: 80%;
color: rgb(226, 28, 28);
display: none;
}` );
        collector( '</style>' );
    }
    
    protected generateBody( collector: Collector ): void {
        collector( '<body> <h1>' );
        collector( this.basicFormTitle )
        collector( '</h1> <div id="error-div" class="error"> <span id="error"></span> </div> <div class="form"> <input type="text" id="username-input" placeholder="' );
        collector( this.basicUserNamePlaceholder );
        collector( '" class="username-input"/> <input type="password" id="password-input" placeholder="' );
        collector( this.basicPasswordPlaceholder );
        collector( '" class="password-input"/> </div> <button id="submit-button">' );
        collector( this.basicSubmitButtonLabel );
        collector( '</button>' );
        this.generateScript( collector );
        collector( '</body>');
    }

    protected generateScript( collector: Collector ): void {
    }
}