using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace CK.AspNet.Auth
{
    static class InternalExtensions
    {
        static public void SetNoCache( this HttpResponse @this, int defaultStatusCode = StatusCodes.Status404NotFound )
        {
            @this.Headers[HeaderNames.CacheControl] = "no-cache";
            @this.Headers[HeaderNames.Pragma] = "no-cache";
            @this.Headers[HeaderNames.Expires] = "-1";
            @this.StatusCode = defaultStatusCode;
        }

        static public Task WriteAsync( this HttpResponse @this, JObject o, int code = StatusCodes.Status200OK )
        {
            @this.StatusCode = code;
            @this.ContentType = "application/json";
            return @this.WriteAsync( o != null ? o.ToString(Newtonsoft.Json.Formatting.None) : "{}" );
        }

    }
}
