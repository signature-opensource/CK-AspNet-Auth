using CK.AspNet.Auth;
using CK.Auth;
using System;
using System.Collections.Generic;
using System.Text;

namespace Microsoft.AspNetCore.Http
{
    /// <summary>
    /// Exposes <see cref="WebFrontAuthenticate"/> extension method on <see cref="HttpContext"/>.
    /// </summary>
    static public class CKAspNetAuthHttpContextExtensions
    {
        /// <summary>
        /// Obtains the current <see cref="IAuthenticationInfo"/>, either because it is already 
        /// in <see cref="HttpContext.Items"/> or by extracting authentication from request.
        /// It is never null, but can be <see cref="IAuthenticationInfoType.None"/>.
        /// </summary>
        /// <param name="this">This context.</param>
        /// <returns>Never null, can be <see cref="IAuthenticationInfoType.None"/>.</returns>
        static public IAuthenticationInfo WebFrontAuthenticate( this HttpContext @this )
        {
            IAuthenticationInfo authInfo = null;
            object o;
            if( @this.Items.TryGetValue( typeof( FrontAuthenticationInfo ), out o ) )
            {
                authInfo = ((FrontAuthenticationInfo)o).Info;
            }
            else
            {
                WebFrontAuthService s = (WebFrontAuthService)@this.RequestServices.GetService( typeof( WebFrontAuthService ) );
                if( s == null ) throw new InvalidOperationException( "Missing WebFrontAuthService registration in Services." );
                authInfo = s.ReadAndCacheAuthenticationHeader( @this ).Info;
            }
            return authInfo;
        }
    }
}
