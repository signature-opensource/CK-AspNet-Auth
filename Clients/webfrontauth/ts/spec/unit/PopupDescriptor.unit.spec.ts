import axios from 'axios';
import { expect } from 'chai';

import { AuthService } from '../../src';
import { PopupDescriptor } from '../../src/index.extension';

describe( 'PopupDescriptor', function() {

    context( 'when defined in an AuthService', function() {

        it( 'should be instanciated by default.', function() {
            const authService = new AuthService( { identityEndPoint: {} }, axios );
            expect( authService.popupDescriptor ).to.not.be.null;
        });
    
        it( 'should not accept null as a new value.', function() {
            const authService = new AuthService( { identityEndPoint: {} }, axios );
            authService.popupDescriptor = null;
            expect( authService.popupDescriptor ).to.not.be.null;

            const customPopupDescriptor = new PopupDescriptor();
            customPopupDescriptor.basicFormTitle = 'Connexion';
            authService.popupDescriptor = customPopupDescriptor;
            expect( authService.popupDescriptor ).to.deep.equal( customPopupDescriptor );
        });

    });

    it( 'should return a valid html', function() {
        const popupDescriptor = new PopupDescriptor();
        const html = popupDescriptor.generateBasicHtml();
        const expectedOutput =
`<!DOCTYPE html> <html> <head> <title> Connection </title> <style> body{
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
} </style> </head> <body> <h1> Connection </h1> <div id="error-div" class="error"> <span id="error"></span> </div> <div class="form"> <input type="text" id="username-input" placeholder=" username " class="username-input"/> <input type="password" id="password-input" placeholder=" password " class="password-input"/> </div> <button id="submit-button"> Submit </button> </body> </html>`;
        expect( html ).to.be.equal( expectedOutput );
    });

    it( 'should be translatable.', function() {
        const popupDescriptor = new PopupDescriptor();
        popupDescriptor.popupTitle = 'Connexion';
        popupDescriptor.basicFormTitle = 'Connexion';
        popupDescriptor.basicUserNamePlaceholder = 'Nom d\'utilisateur';
        popupDescriptor.basicPasswordPlaceholder = 'Mot de passe';
        popupDescriptor.basicSubmitButtonLabel = 'Se connecter';
        const html = popupDescriptor.generateBasicHtml();
        const expectedOutput =
`<!DOCTYPE html> <html> <head> <title> Connexion </title> <style> body{
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
} </style> </head> <body> <h1> Connexion </h1> <div id="error-div" class="error"> <span id="error"></span> </div> <div class="form"> <input type="text" id="username-input" placeholder=" Nom d'utilisateur " class="username-input"/> <input type="password" id="password-input" placeholder=" Mot de passe " class="password-input"/> </div> <button id="submit-button"> Se connecter </button> </body> </html>`;
        expect( html ).to.be.equal( expectedOutput );
    });
});