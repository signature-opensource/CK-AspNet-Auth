using CK.Auth;
using CK.Core;
using CK.Testing;
using Shouldly;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace CK.AspNet.Auth.Tests;

static class LocalHelper
{
    public static Task<RunningAspNetServer> CreateLocalAuthServerAsync( Action<IServiceCollection>? configureServices = null,
                                                                        Action<IApplicationBuilder>? configureApplication = null,
                                                                        Action<WebFrontAuthOptions>? webFrontAuthOptions = null )
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Services.AddSingleton<AuthenticationInfoTokenService>();
        builder.Services.AddSingleton<IAuthenticationTypeSystem, StdAuthenticationTypeSystem>();
        builder.Services.AddSingleton<FakeWebFrontAuthLoginService>();
        builder.Services.AddSingleton<IWebFrontAuthLoginService>( sp => sp.GetRequiredService<FakeWebFrontAuthLoginService>() );
        builder.Services.AddSingleton<FakeUserDatabase>();
        builder.Services.AddSingleton<IUserInfoProvider>( sp => sp.GetRequiredService<FakeUserDatabase>() );
        builder.Services.AddScoped<IActivityMonitor, ActivityMonitor>();
        builder.Services.AddScoped<IParallelLogger>( sp => sp.GetRequiredService<IParallelLogger>() );
        builder.AddWebFrontAuth( webFrontAuthOptions );
        configureServices?.Invoke( builder.Services );

        return builder.CreateRunningAspNetServerAsync( configureApplication: app =>
        {
            app.Use( next =>
            {
                return async ctx =>
                {
                    if( ctx.Request.Path.StartsWithSegments( "/echo", out var remaining ) )
                    {
                        var echo = remaining.ToString();
                        if( ctx.Request.QueryString.HasValue ) echo += " => " + ctx.Request.QueryString;

                        if( remaining.StartsWithSegments( "/error", out var errorCode ) && Int32.TryParse( errorCode, out var error ) )
                        {
                            ctx.Response.StatusCode = error;
                            echo += $" (StatusCode set to '{error}')";
                        }
                        if( ctx.Request.Query.ContainsKey( "userName" ) )
                        {
                            var authInfo = CKAspNetAuthHttpContextExtensions.GetAuthenticationInfo( ctx );
                            echo += $" (UserName: '{authInfo.User.UserName}')";
                        }
                        await ctx.Response.Body.WriteAsync( System.Text.Encoding.UTF8.GetBytes( echo ) );
                    }
                    else if( ctx.Request.Path.StartsWithSegments( "/CallChallengeAsync", out _ ) )
                    {
                        await Microsoft.AspNetCore.Authentication.AuthenticationHttpContextExtensions.ChallengeAsync( ctx );
                        ctx.User.Identity!.Name.ShouldBe( "Albert" );
                    }
                    else if( ctx.Request.Path.StartsWithSegments( "/ComingFromCris/LogoutCommand", out _ ) )
                    {
                        var s = app.Services.GetRequiredService<WebFrontAuthService>();
                        await s.LogoutCommandAsync( new ActivityMonitor(), ctx );
                        ctx.Response.StatusCode = 200;
                    }
                    else if( ctx.Request.Path.StartsWithSegments( "/ComingFromCris/LoginCommand", out _ ) )
                    {
                        var s = app.Services.GetRequiredService<WebFrontAuthService>();
                        var r = await s.BasicLoginCommandAsync( new ActivityMonitor(),
                                                                ctx,
                                                                ctx.Request.Query["userName"],
                                                                "success",
                                                                impersonateActualUser: ctx.Request.Query["impersonateActualUser"] == "True" );
                        ctx.Response.StatusCode = 200;
                        Throw.DebugAssert( r.Token != null );
                        await ctx.Response.WriteAsync( r.Token );
                    }
                    else
                    {
                        await next( ctx );
                    }
                };
            } );
            configureApplication?.Invoke( app );
        } );
    }

    public static async Task<AuthServerResponse> LoginViaLocalCommandAsync( this RunningAspNetServer.RunningClient client,
                                                                            string userName,
                                                                            bool impersonateActualUser = false )
    {
        using HttpResponseMessage getResponse = await client.GetAsync( $"/ComingFromCris/LoginCommand?userName={userName}&impersonateActualUser={impersonateActualUser}" );
        var token = await getResponse.Content.ReadAsStringAsync();
        client.Token = token;
        var r = await client.AuthenticationRefreshAsync();
        return r;
    }

}
