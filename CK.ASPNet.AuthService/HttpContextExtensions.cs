using CK.Auth;
using System;
using System.Collections.Generic;
using System.Text;

namespace Microsoft.AspNetCore.Http
{
    static public class HttpContextExtensions
    {
        static public IAuthenticationInfo GetAuthenticationInfo( this HttpContext @this )
        {
            object o;
            @this.Items.TryGetValue(typeof(IAuthenticationInfo), out o);
            return o as IAuthenticationInfo;
        }
    }
}
