using CK.AspNet.Auth;
using CK.Auth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Text;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class WebFrontAuthExtensions
    {
        public static AuthenticationBuilder AddWebFrontAuth( this AuthenticationBuilder @this )
        {
            return @this.AddWebFrontAuth<StdAuthenticationTypeSystem>( null );
        }

        public static AuthenticationBuilder AddWebFrontAuth( this AuthenticationBuilder @this, Action<WebFrontAuthOptions> configure )
        {
            return @this.AddWebFrontAuth<StdAuthenticationTypeSystem>( configure );
        }

        public static AuthenticationBuilder AddWebFrontAuth<TTypeSystem>( this AuthenticationBuilder @this, Action<WebFrontAuthOptions> configure )
            where TTypeSystem : class, IAuthenticationTypeSystem
        {
            @this.Services.AddSingleton<IAuthenticationTypeSystem, TTypeSystem>();
            @this.Services.AddSingleton<WebFrontAuthService>();
            @this.AddScheme<WebFrontAuthOptions, WebFrontAuthHandler>( WebFrontAuthOptions.OnlyAuthenticationScheme, "Web Front Authentication", configure );
            return @this;
        }
    }
}
