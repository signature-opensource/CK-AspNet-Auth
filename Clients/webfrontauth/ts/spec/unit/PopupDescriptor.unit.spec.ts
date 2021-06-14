import axios from 'axios';

import { AuthService } from '../../src';
import { PopupDescriptor } from '../../src/index';

describe('PopupDescriptor', function () {
    const axiosInstance = axios.create({ timeout: 0.1 });

    describe('when defined in an AuthService', function () {

        it('should be instanciated by default.', function () {
            const authService = new AuthService({ identityEndPoint: {} }, axiosInstance);
            expect(authService.popupDescriptor).not.toBeNull();
        });

        it('should not accept a custom descriptor.', function () {
            const authService = new AuthService({ identityEndPoint: {} }, axiosInstance);
            expect(authService.popupDescriptor).not.toBeNull();

            const customPopupDescriptor = new PopupDescriptor();
            customPopupDescriptor.basicFormTitle = 'Connexion';
            authService.popupDescriptor = customPopupDescriptor;
            expect(authService.popupDescriptor).toEqual(customPopupDescriptor);
        });

    });

    it('should return a valid html.', function () {
        const popupDescriptor = new PopupDescriptor();
        const html = popupDescriptor.generateBasicHtml( true );
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
} </style> </head> <body> <h1> Connection </h1> <div id="error-div" class="error"> <span id="error"></span> </div> <div class="form"> <input type="text" id="username-input" placeholder=" username " class="username-input"/> <input type="password" id="password-input" placeholder=" password " class="password-input"/> <input type="checkbox" id="remember-me-input" checked class="remember-me-input"/> <label for="remember-me-input" class="remember-me-label"> Remember me </label> </div> <button id="submit-button"> Submit </button> </body> </html>`;
        expect(html).toEqual(expectedOutput);
    });

    it('should be translatable.', function () {
        const popupDescriptor = new PopupDescriptor();
        popupDescriptor.popupTitle = 'Connexion';
        popupDescriptor.basicFormTitle = 'Connexion';
        popupDescriptor.basicUserNamePlaceholder = 'Nom d\'utilisateur';
        popupDescriptor.basicPasswordPlaceholder = 'Mot de passe';
        popupDescriptor.basicSubmitButtonLabel = 'Se connecter';
        popupDescriptor.basicRememberMeLabel = 'Se souvenir de moi';
        const html = popupDescriptor.generateBasicHtml( false );
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
} </style> </head> <body> <h1> Connexion </h1> <div id="error-div" class="error"> <span id="error"></span> </div> <div class="form"> <input type="text" id="username-input" placeholder=" Nom d'utilisateur " class="username-input"/> <input type="password" id="password-input" placeholder=" Mot de passe " class="password-input"/> <input type="checkbox" id="remember-me-input" class="remember-me-input"/> <label for="remember-me-input" class="remember-me-label"> Se souvenir de moi </label> </div> <button id="submit-button"> Se connecter </button> </body> </html>`;
        expect(html).toEqual(expectedOutput);
    });
});
