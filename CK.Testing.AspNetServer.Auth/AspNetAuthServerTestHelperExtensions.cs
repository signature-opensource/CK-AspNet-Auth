using CK.AspNet.Auth;
using CK.Auth;
using CK.Core;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using System;
using System.Threading.Tasks;

namespace CK.Testing
{
    /// <summary>
    /// Expose <see cref="CreateRunningAspNetAuthenticationServerAsync"/>.
    /// </summary>
    public static class AspNetAuthServerTestHelperExtensions
    {
        /// <summary>
        /// Creates, configures and starts a <see cref="RunningAspNetServer"/> that supports authentication with
        /// <see cref="WebFrontAuthExtensions.AddUnsafeAllowAllCors(WebApplicationBuilder)"/> (this is for tests only).
        /// <para>
        /// If this <see cref="IStObjMap"/> doesn't have a <see cref="IWebFrontAuthLoginService"/> implementation,
        /// the <see cref="FakeWebFrontAuthLoginService"/> is automatically registered and if no <see cref="IUserInfoProvider"/>
        /// exists, the <see cref="FakeUserDatabase"/> is automatically registered.
        /// </para>
        /// </summary>
        /// Note: <c>IUserInfoProvider</c> and <c>IWebFrontAuthLoginService</c> must obviously be coupled somehow. ISP principle
        /// made us separate the 2 concerns but implementations should be coherent. This cannot be challenged
        /// here (and in a way it shouldn't be).
        /// <remarks>
        /// </remarks>
        /// <param name="map">This StObjMap.</param>
        /// <param name="authOptions">Optional option configuration.</param>
        /// <param name="configureApplication">Optional application configurator.</param>
        /// <returns>A running Asp.NET server with authentication support.</returns>
        public static Task<RunningAspNetServer> CreateRunningAspNetAuthenticationServerAsync( this WebApplicationBuilder builder,
                                                                                             IStObjMap map,
                                                                                             Action<WebFrontAuthOptions>? authOptions = null,
                                                                                             Action<IApplicationBuilder>? configureApplication = null )
        {
            // Use TryAdd to allow manual services configuration if the CKomposable map is missing it.
            if( !map.Services.Mappings.ContainsKey( typeof( IUserInfoProvider ) ) )
            {
                builder.Services.TryAddSingleton<IUserInfoProvider, FakeUserDatabase>();
            }
            if( !map.Services.Mappings.ContainsKey( typeof( IWebFrontAuthLoginService ) ) )
            {
                builder.Services.TryAddSingleton<FakeUserDatabase>();
                builder.Services.TryAddSingleton<IWebFrontAuthLoginService, FakeWebFrontAuthLoginService>();
            }
            builder.AddUnsafeAllowAllCors();
            builder.AddWebFrontAuth( authOptions );
            return builder.CreateRunningAspNetServerAsync( map, configureApplication );
        }

    }
}
