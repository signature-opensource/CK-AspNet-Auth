using CK.AspNet.Auth;
using CK.Auth;
using CK.Core;
using CK.Setup;
using FluentAssertions.Common;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.Testing
{
    /// <summary>
    /// Offers <see cref=""/>
    /// and <see cref="CreateAspNetAuthServerAsync(BinPathConfiguration, Action{IServiceCollection}?, Action{IApplicationBuilder}?, Action{WebFrontAuthOptions}?)"/>
    /// helpers.
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
        /// <param name="authOptions">
        /// Optional authentication options configurator.
        /// By default <see cref="WebFrontAuthOptions.SlidingExpirationTime"/> is set to 10 minutes.
        /// </param>
        /// <param name="configureApplication">Optional application configurator.</param>
        /// <returns>A running Asp.NET server with authentication support.</returns>
        public static Task<RunningAspNetServer> CreateRunningAspNetAuthServerAsync( this WebApplicationBuilder builder,
                                                                                    IStObjMap map,
                                                                                    Action<WebFrontAuthOptions>? authOptions = null,
                                                                                    Action<IApplicationBuilder>? configureApplication = null )
        {
            if( !map.Services.Mappings.ContainsKey( typeof( IUserInfoProvider ) ) )
            {
                // Use TryAdd to allow the configureServices function to inject its IUserInfoProvider
                // if the CKomposable map is missing it.
                builder.Services.TryAddSingleton<IUserInfoProvider, FakeUserDatabase>();
            }
            if( !map.Services.Mappings.ContainsKey( typeof( IWebFrontAuthLoginService ) ) )
            {
                // Use TryAdd to allow the configureServices function to inject its IWebFrontAuthLoginService
                // if the CKomposable map is missing it.
                builder.Services.TryAddSingleton<IWebFrontAuthLoginService, FakeWebFrontAuthLoginService>();
            }
            builder.AddWebFrontAuth( authOptions );
            builder.AddUnsafeAllowAllCors();
            return builder.CreateRunningAspNetServerAsync( configureApplication );
        }

    }
}
