using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace CK.AspNet.Auth
{
    public static class InternalExtensions
    {
        static public void SetNoCacheAndDefaultStatus( this HttpResponse @this, int defaultStatusCode )
        {
            @this.Headers[HeaderNames.CacheControl] = "no-cache";
            @this.Headers[HeaderNames.Pragma] = "no-cache";
            @this.Headers[HeaderNames.Expires] = "-1";
            @this.StatusCode = defaultStatusCode;
        }

        static public bool TryReadSmallBodyAsString( this HttpRequest @this, out string body, int maxLen )
        {
           body = null;
           using( var s = new StreamReader( @this.Body, Encoding.UTF8, true, 1024, true ) )
            {
                char[] max = new char[maxLen];
                int len = s.ReadBlock( max, 0, maxLen );
                if( !s.EndOfStream )
                {
                    @this.HttpContext.Response.StatusCode = StatusCodes.Status400BadRequest;
                    return false;
                }
                body = new String( max, 0, len );
                return true;
            }
        }

        static public Task WriteAsync( this HttpResponse @this, JObject o, int code = StatusCodes.Status200OK )
        {
            @this.StatusCode = code;
            @this.ContentType = "application/json";
            return @this.WriteAsync( o != null ? o.ToString( Newtonsoft.Json.Formatting.None ) : "{}" );
        }

        static public Task WriteErrorAsync( this HttpResponse @this, Exception ex, int code )
        {
            var error = new JObject(
                new JProperty( "errorId", ex.GetType().FullName ),
                new JProperty( "errorText", ex.Message ) );
            return WriteAsync( @this, error, code );
        }

        static public void RedirectToReturnUrlWithError( this HttpResponse @this,
            Exception ex,
            string initialScheme = null,
            string callingScheme = null )
        {
            RedirectToReturnUrlWithError( @this, ex.GetType().FullName, ex.Message, initialScheme, callingScheme );
        }

        static public void RedirectToReturnUrlWithError( this HttpResponse @this, 
            string returnUrl,
            string errorId,
            string errorText,
            string initialScheme = null,
            string callingScheme = null )
        {
            var retUrl = new Uri( returnUrl, UriKind.RelativeOrAbsolute );
            var parameters = new QueryString( retUrl.Query );
            parameters.Add( "errorId", errorId );
            parameters.Add( "errorText", errorText );
            if( initialScheme != null ) parameters.Add( "initialScheme", initialScheme );
            if( callingScheme != null ) parameters.Add( "callingScheme", callingScheme );

            var caller = new Uri( $"{@this.HttpContext.Request.Scheme}://{@this.HttpContext.Request.Host}/" );
            var target = new Uri( caller, retUrl.AbsolutePath + parameters.Value );
            @this.Redirect( target.ToString() );
        }

        static public Task WritePostMessageWithErrorAsync( this HttpResponse @this,
            Exception ex,
            string initialScheme = null,
            string callingScheme = null,
            JProperty userData = null )
        {
            return WritePostMessageWithErrorAsync( @this, ex.GetType().FullName, ex.Message, initialScheme, callingScheme, userData );
        }

        static public Task WritePostMessageWithErrorAsync( this HttpResponse @this,
            string errorId,
            string errorText,
            string initialScheme = null,
            string callingScheme = null,
            JProperty userData = null )
        {
            var error = new JObject(
                new JProperty( "errorId", errorId ),
                new JProperty( "errorText", errorText ) );
            if( initialScheme != null ) error.Add( new JProperty( "initialScheme", initialScheme ) );
            if( callingScheme != null ) error.Add( new JProperty( "callingScheme", callingScheme ) );
            if( userData != null ) error.Add( userData );
            return WritePostMessageAsync( @this, error );
        }

        static public Task WritePostMessageAsync( this HttpResponse @this, JObject o )
        {
            var req = @this.HttpContext.Request;
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
window.opener.postMessage( {oS}, '{req.Scheme}://{req.Host}/');
window.close();
}})();
</script>
<!--{GetBreachPadding()}-->
</body>
</html>";
            return @this.WriteAsync( r );
        }

        static public Task WritePostRedirectEndLoginAsync( this HttpResponse @this, string secureData, string returnUrl )
        {
            var req = @this.HttpContext.Request;
            @this.StatusCode = StatusCodes.Status200OK;
            @this.ContentType = "text/html";
            var r = $@"<!DOCTYPE html>
<html><body>
<form method='post' action='{req.Scheme}://{req.Host}/.webfront/c/endLogin'>
<input type='hidden' name='s' value='{secureData}' />
<input type='hidden' name='r' value='{returnUrl}' />
</form><script>(function(){{document.forms[0].submit();}})();</script>
<!--{GetBreachPadding()}-->
</body></html>";
            return @this.WriteAsync( r );
        }

        static string GetBreachPadding()
        {
            Random random = new Random();
            byte[] data = new byte[random.Next( 64, 256 )];
            random.NextBytes( data );
            return Convert.ToBase64String( data );
        }
    }
}
