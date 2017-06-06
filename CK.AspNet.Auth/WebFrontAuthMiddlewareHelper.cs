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
                    var featureRequest = c.Features[typeof( Microsoft.AspNetCore.Http.Features.IHttpRequestFeature )] as Microsoft.AspNetCore.Http.Features.IHttpRequestFeature;
                    if( featureRequest != null && !featureRequest.RawTarget.StartsWith("/.webfront/c/startLogin?"))
                    {
                        throw new InvalidOperationException( "Must be called only from /.webfront/c/startLogin." );
                    }
                    string provider = c.Request.Query["provider"];
                    if( provider == null )
                    {
                        c.Response.StatusCode = StatusCodes.Status400BadRequest;
                        return Task.CompletedTask;
                    }
                    IEnumerable<KeyValuePair<string, StringValues>> userData = HttpMethods.IsPost( c.Request.Method )
                                                                                ? c.Request.Form
                                                                                : c.Request.Query.Where( k => k.Key != "provider" );
                    var current = _authService.EnsureAuthenticationInfo( c );

                    AuthenticationProperties p = new AuthenticationProperties();
                    p.Items.Add( "WFA-P", provider );
                    if( !current.IsNullOrNone() ) p.Items.Add( "WFA-C", _authService.ProtectAuthenticationInfo( c, current ) );
                    if( userData.Any() ) p.Items.Add( "WFA-D", _authService.ProtectExtraData( c, userData ) );

                    return c.Authentication.ChallengeAsync( provider, p );
                }
                return Task.CompletedTask;
            }
            return _next.Invoke( c );
        }

    }
}
