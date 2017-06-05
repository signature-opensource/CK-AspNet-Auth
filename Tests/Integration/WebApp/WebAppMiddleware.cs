using CK.AspNet;
using CK.AspNet.Auth;
using CK.DB.Actor;
using CK.DB.User.UserPassword;
using CK.SqlServer;
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
using System.Threading.Tasks;

namespace WebApp
{
    public class WebAppMiddleware
    {
        readonly RequestDelegate _next;
        readonly WebFrontAuthService _authService;
        readonly UserTable _userTable;
        readonly UserPasswordTable _pwdTable;
        static readonly PathString _root = "/app";

        public WebAppMiddleware( 
            RequestDelegate next,
            WebFrontAuthService authService,
            UserPasswordTable pwdTable,
            UserTable userTable )
        {
            _next = next;
            _authService = authService;
            _pwdTable = pwdTable;
            _userTable = userTable;
        }

        public Task Invoke( HttpContext c )
        {
            PathString remainder;
            if( c.Request.Path.StartsWithSegments( _root, out remainder ) )
            {
                c.Response.Headers[HeaderNames.CacheControl] = "no-cache";
                c.Response.Headers[HeaderNames.Pragma] = "no-cache";
                c.Response.Headers[HeaderNames.Expires] = "-1";
                c.Response.StatusCode = StatusCodes.Status404NotFound;
                if( remainder.StartsWithSegments("/ensureBasicUser") )
                {
                    if( HttpMethods.IsPost( c.Request.Method ) ) return EnsureBasicUser( c, c.Request, c.Response );
                    c.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
                    return Task.CompletedTask;
                }
                if( remainder.StartsWithSegments("/try") )
                {
                    string provider = c.Request.Query["provider"];
                    AuthenticationProperties p = new AuthenticationProperties();
                    p.Items.Add( "Test", "TestValues" );
                    return c.Authentication.ChallengeAsync( provider, p );
                }
                // Default response for app/... paths.
                c.Response.StatusCode = StatusCodes.Status200OK;
                return c.Response.WriteAsync( "UserName: " + c.WebFrontAuthenticate().User.UserName );
            }
            return _next.Invoke( c );
        }

        async Task EnsureBasicUser( HttpContext c, HttpRequest req, HttpResponse resp )
        {
            var b = await new StreamReader( req.Body ).ReadToEndAsync();
            var r = JObject.Parse( b );
            ISqlCallContext ctx = c.GetSqlCallContext();
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

    }
}
