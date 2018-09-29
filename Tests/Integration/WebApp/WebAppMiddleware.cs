using CK.AspNet;
using CK.AspNet.Auth;
using CK.DB.Actor;
using CK.DB.User.UserPassword;
using CK.SqlServer;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.Net.Http.Headers;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using CK.Auth;
using Microsoft.AspNetCore.Hosting;
using CK.Core;

namespace WebApp
{
    public class WebAppMiddleware
    {
        readonly RequestDelegate _next;
        readonly WebFrontAuthService _authService;
        readonly UserTable _userTable;
        readonly UserPasswordTable _pwdTable;
        readonly IAuthenticationTypeSystem _typeSystem;
        readonly IApplicationLifetime _appLifetime;

        public WebAppMiddleware( 
            RequestDelegate next,
            WebFrontAuthService authService,
            IAuthenticationTypeSystem typeSystem,
            UserPasswordTable pwdTable,
            UserTable userTable,
            IApplicationLifetime appLifetime )
        {
            _next = next;
            _authService = authService;
            _pwdTable = pwdTable;
            _userTable = userTable;
            _typeSystem = typeSystem;
            _appLifetime = appLifetime;
        }

        public async Task Invoke( HttpContext c )
        {
            c.Response.Headers[HeaderNames.CacheControl] = "no-cache";
            c.Response.Headers[HeaderNames.Pragma] = "no-cache";
            c.Response.Headers[HeaderNames.Expires] = "-1";
            c.Response.StatusCode = StatusCodes.Status404NotFound;

            var path = c.Request.Path;

            if( path.StartsWithSegments( "/ensureBasicUser" ) )
            {
                if( HttpMethods.IsPost( c.Request.Method ) )
                {
                    await EnsureBasicUser( c, c.Request, c.Response );
                }
                else
                {
                    c.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
                }
                return;
            }
            if( path.StartsWithSegments( "/test" ) )
            {
                c.Response.StatusCode = StatusCodes.Status200OK;
                c.Response.ContentType = "application/json";
                ISqlCallContext sqlCtx = c.RequestServices.GetService<ISqlCallContext>();
                IActivityMonitor m = sqlCtx.Monitor;
                IActivityMonitor reqMonitor = c.RequestServices.GetService<IActivityMonitor>();
                await c.Response.WriteAsync( $@"{{ ""IAmHere"": true, ""Monitor"": {m != null}, ""SqlCallContext"": {sqlCtx != null}, ""SqlCallContext.Monitor"": {m==reqMonitor} }}" );
                return;
            }
            if( path.StartsWithSegments( "/quit" ) )
            {
                c.Response.StatusCode = StatusCodes.Status200OK;
                _appLifetime.StopApplication();
                return;
            }
            c.Response.StatusCode = StatusCodes.Status200OK;
            await WriteHtmlAsync( c.Response, async r =>
            {
                await r.WriteAsync( "<h1>Actions</h1>" );
                await r.WriteAsync( @"Login via Google - <a href=""/.webfront/c/startLogin?scheme=Google&returnUrl="">[inline]</a> <a href=""/.webfront/c/startLogin?scheme=Google"">[popup]</a><br>" );
                await r.WriteAsync( @"Login via OpenIdConnect <a href=""/.webfront/c/startLogin?scheme=oidc&returnUrl="">[inline]</a> <a href=""/.webfront/c/startLogin?scheme=oidc"">[popup]</a><br>" );
                await r.WriteAsync( @"<a href=""/.webfront/c/refresh"">[Refresh]</a> <a href=""/.webfront/c/refresh?shemes"">[Refresh with schemes]</a><br>" );
                await r.WriteAsync( @"<a href=""/.webfront/c/logout"">[Logout]</a><br>" );
                await r.WriteAsync( @"<a href=""/test"">[Test]</a><br>" );
                await r.WriteAsync( @"<a href=""/quit"">[Quit]</a><br>" );
            } );
        }

        async Task EnsureBasicUser( HttpContext c, HttpRequest req, HttpResponse resp )
        {
            var b = await new StreamReader( req.Body ).ReadToEndAsync();
            var r = JObject.Parse( b );
            ISqlCallContext ctx = c.RequestServices.GetService<ISqlCallContext>();
            var userName = (string)r["userName"];
            int userId = await _userTable.CreateUserAsync( ctx, 1, userName );
            if( userId < 0 )
            {
                userId = await _userTable.FindByNameAsync( ctx, userName );
            }
            if( userId < 0 )
            {
                resp.StatusCode = StatusCodes.Status403Forbidden;
            }
            else
            {
                await _pwdTable.CreateOrUpdatePasswordUserAsync( ctx, 1, userId, (string)r["password"] );
                resp.StatusCode = StatusCodes.Status200OK;
            }
        }

        private static async Task WriteHtmlAsync( HttpResponse response, Func<HttpResponse, Task> writeContent )
        {
            response.ContentType = "text/html";
            var bootstrap = "<link rel=\"stylesheet\" href=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css\" integrity=\"sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u\" crossorigin=\"anonymous\">";
            await response.WriteAsync( $"<html><head>{bootstrap}</head><body><div class=\"container\">" );
            await writeContent( response );
            await response.WriteAsync( "</div></body></html>" );
        }

        private static async Task WriteTableHeader( HttpResponse response, IEnumerable<string> columns, IEnumerable<IEnumerable<string>> data )
        {
            await response.WriteAsync( "<table class=\"table table-condensed\">" );
            await response.WriteAsync( "<tr>" );
            foreach( var column in columns )
            {
                await response.WriteAsync( $"<th>{HtmlEncode( column )}</th>" );
            }
            await response.WriteAsync( "</tr>" );
            foreach( var row in data )
            {
                await response.WriteAsync( "<tr>" );
                foreach( var column in row )
                {
                    await response.WriteAsync( $"<td>{HtmlEncode( column )}</td>" );
                }
                await response.WriteAsync( "</tr>" );
            }
            await response.WriteAsync( "</table>" );
        }

        private static string HtmlEncode( string content ) =>
            string.IsNullOrEmpty( content ) ? string.Empty : HtmlEncoder.Default.Encode( content );
    }
}
