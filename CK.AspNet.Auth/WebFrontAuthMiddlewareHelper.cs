using CK.AspNet;
using CK.AspNet.Auth;
using CK.Auth;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.Extensions.Primitives;
using Microsoft.Net.Http.Headers;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace CK.AspNet.Auth
{
    public class WebFrontAuthMiddlewareHelper
    {
        readonly RequestDelegate _next;
        readonly WebFrontAuthService _authService;

        public WebFrontAuthMiddlewareHelper( 
            RequestDelegate next,
            WebFrontAuthService authService )
        {
            _next = next;
            _authService = authService;
        }

        public Task Invoke( HttpContext c )
        {
            PathString remainder;
            if( c.Request.Path.StartsWithSegments( "/.webfrontHelper", out remainder ) )
            {
                c.Response.Headers[HeaderNames.CacheControl] = "no-cache";
                c.Response.Headers[HeaderNames.Pragma] = "no-cache";
                c.Response.Headers[HeaderNames.Expires] = "-1";
                c.Response.StatusCode = StatusCodes.Status404NotFound;
                if( remainder.StartsWithSegments("/startLogin") )
                {
                    //string provider = c.Request.Query["provider"];
                    //string current = c.Request.Query["c"];
                    //string extraData = c.Request.Query["d"];
                    //AuthenticationProperties p = new AuthenticationProperties();
                    //if( current != null ) p.Items.Add( "WFACurrent", current );
                    //if( extraData != null ) p.Items.Add( "WFAExtra", extraData );
                    //return c.Authentication.ChallengeAsync( provider, p );

                    string provider = c.Request.Query["provider"];
                    AuthenticationProperties p = new AuthenticationProperties();
                    p.Items.Add( "Test", "TestValues" );
                    return c.Authentication.ChallengeAsync( provider, p );

                }
                return Task.FromResult(true);
            }
            return _next.Invoke( c );
        }

    }
}
