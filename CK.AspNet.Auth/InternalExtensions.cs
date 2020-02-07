using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using Microsoft.Net.Http.Headers;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CK.AspNet.Auth
{
    static class InternalExtensions
    {
        static public JProperty ToJProperty( this IEnumerable<KeyValuePair< string,StringValues>> @this, string name = "userData" )
        {
            return new JProperty( name,
                            new JObject( @this.Select( d => new JProperty( d.Key,
                                                                              d.Value.Count == 1
                                                                                ? (JToken)d.Value.ToString()
                                                                                : new JArray( d.Value ) ) ) ) );
        }

        static public void SetNoCacheAndDefaultStatus( this HttpResponse @this, int defaultStatusCode )
        {
            @this.Headers[HeaderNames.CacheControl] = "no-cache";
            @this.Headers[HeaderNames.Pragma] = "no-cache";
            @this.Headers[HeaderNames.Expires] = "-1";
            @this.StatusCode = defaultStatusCode;
        }

        /// <summary>
        /// Reads a limited number of characters from the request body (with an UTF8 encoding).
        /// </summary>
        /// <param name="this">This request.</param>
        /// <param name="maxLen">The maximal number of characters to read.</param>
        /// <returns>The string or null on error.</returns>
        static public async Task<string> TryReadSmallBodyAsString( this HttpRequest @this, int maxLen )
        {
            using( var s = new StreamReader( @this.Body, Encoding.UTF8, true, 1024, true ) )
            {
                char[] max = new char[maxLen + 1];
                int len = await s.ReadBlockAsync( max, 0, maxLen + 1 );
                if( len >= maxLen )
                {
                    @this.HttpContext.Response.StatusCode = StatusCodes.Status400BadRequest;
                    return null;
                }
                return new String( max, 0, len );
            }
        }

        static public Task WriteAsync( this HttpResponse @this, JObject o, int code = StatusCodes.Status200OK )
        {
            @this.StatusCode = code;
            @this.ContentType = "application/json";
            return @this.WriteAsync( o != null ? o.ToString( Newtonsoft.Json.Formatting.None ) : "{}" );
        }

        static public Task WriteWindowPostMessageAsync( this HttpResponse @this, JObject o, string callerOrigin )
        {
            @this.StatusCode = StatusCodes.Status200OK;
            @this.ContentType = "text/html";
            var oS = o != null ? o.ToString( Newtonsoft.Json.Formatting.None ) : "{}";
            var r = $@"<!DOCTYPE html>
<html>
<head>
    <meta name=""viewport"" content=""width=device-width"" />
    <title>Conclusion</title>
</head>
<body>
<script>
(function(){{
window.opener.postMessage( {{""WFA"": ""WFA"", ""data"": {oS} }}, '{callerOrigin}');
window.close();
}})();
</script>
<!--{GetBreachPadding()}-->
</body>
</html>";
            return @this.WriteAsync( r );
        }

        static string GetBreachPadding()
        {
            Random random = new Random();
            byte[] data = new byte[random.Next( 10, 256 )];
            random.NextBytes( data );
            return Convert.ToBase64String( data );
        }
    }
}
