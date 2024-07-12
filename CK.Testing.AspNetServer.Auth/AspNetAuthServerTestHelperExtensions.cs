using CK.AspNet.Auth;
using CK.Auth;
using CK.Core;
using CK.Setup;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using System;
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
        /// Creates, configures and starts a <see cref="RunningAspNetServer"/> that supports authentication.
        /// <para>
        /// This is based on <see cref="AspNetServerTestHelperExtensions.CreateMinimalAspNetServerAsync(IMonitorTestHelper, Action{IServiceCollection}?, Action{IApplicationBuilder}?)"/>
        /// and no services or middlewares other than CORS support (configured without any restriction) and authentication support with the
        /// <see cref="WebFrontAuthService"/> is added.
        /// </para>
        /// <para>
        /// The <see cref="CreateAspNetAuthServerAsync(IStObjMap, Action{IServiceCollection}?, Action{AuthenticationBuilder}?, Action{IApplicationBuilder}?, Action{WebFrontAuthOptions}?)"/>
        /// extension method is easier to use as the CKomposable takes care of all the required automatic services and handles the <see cref="FakeWebFrontAuthLoginService"/>
        /// and <see cref="FakeUserDatabase"/> if needed.
        /// </para>
        /// </summary>
        /// <param name="helper">This helper.</param>
        /// <param name="configureServices">Application services configurator must at least provide a <see cref="WebFrontAuthService"/> implementation.</param>
        /// <param name="configureAuth">Optional authentication configurator.</param>
        /// <param name="configureApplication">Optional application configurator.</param>
        /// <param name="webFrontAuthOptions">Optional authentication options configurator.</param>
        /// <returns>A running Asp.NET server with authentication support.</returns>
        public static Task<RunningAspNetServer> CreateAspNetAuthServerAsync( this IMonitorTestHelper helper,
                                                                             Action<IServiceCollection> configureServices,
                                                                             Action<AuthenticationBuilder>? configureAuth = null,
                                                                             Action<IApplicationBuilder>? configureApplication = null,
                                                                             Action<WebFrontAuthOptions>? webFrontAuthOptions = null )
        {
            Throw.CheckNotNullArgument( configureServices );

            static void ConfigureServices( IServiceCollection services,
                                           Action<IServiceCollection>? configureServices,
                                           Action<AuthenticationBuilder>? configureAuth,
                                           Action<WebFrontAuthOptions>? webFrontAuthOptions )
            {
                services.AddCors();
                var authBuilder = services.AddAuthentication( WebFrontAuthOptions.OnlyAuthenticationScheme )
                                          .AddWebFrontAuth( webFrontAuthOptions );
                configureAuth?.Invoke( authBuilder );
                configureServices?.Invoke( services );
            }

            static void ConfigureApplication( IApplicationBuilder app, Action<IApplicationBuilder>? configureApplication )
            {
                app.UseCors( o => o.AllowAnyMethod().AllowCredentials().AllowAnyHeader().SetIsOriginAllowed( _ => true ) );
                app.UseAuthentication();
                configureApplication?.Invoke( app );
            }

            return helper.CreateMinimalAspNetServerAsync( configureServices: services => ConfigureServices( services, configureServices, configureAuth, webFrontAuthOptions ),
                                                          configureApplication: app => ConfigureApplication( app, configureApplication ) );
        }

        /// <summary>
        /// Creates, configures and starts a <see cref="RunningAspNetServer"/> that supports authentication.
        /// <para>
        /// If this <see cref="IStObjMap"/> doesn't have a <see cref="IWebFrontAuthLoginService"/> implementation,
        /// the <see cref="FakeWebFrontAuthLoginService"/> is automatically registered and if no <see cref="IUserInfoProvider"/>
        /// exists, the <see cref="FakeUserDatabase"/> is automatically registered.
        /// </para>
        /// </summary>
        /// <param name="map">This StObjMap.</param>
        /// <param name="configureServices">Optional application services configurator.</param>
        /// <param name="configureAuth">Optional authentication configurator.</param>
        /// <param name="configureApplication">Optional application configurator.</param>
        /// <param name="webFrontAuthOptions">
        /// Optional authentication options configurator.
        /// By default <see cref="WebFrontAuthOptions.SlidingExpirationTime"/> is set to 10 minutes.
        /// </param>
        /// <returns>A running Asp.NET server with authentication support.</returns>
        public static Task<RunningAspNetServer> CreateAspNetAuthServerAsync( this IStObjMap map,
                                                                             Action<IServiceCollection>? configureServices = null,
                                                                             Action<AuthenticationBuilder>? configureAuth = null,
                                                                             Action<IApplicationBuilder>? configureApplication = null,
                                                                             Action<WebFrontAuthOptions>? webFrontAuthOptions = null )
        {
            static void ConfigureServices( IServiceCollection services,
                                           IStObjMap map,
                                           Action<IServiceCollection>? configureServices )
            {
                configureServices?.Invoke( services );
                // It is not possible to transfer the "Fake" handling to the IMonitorTestHelper.CreateAspNetAuthServerAsync method
                // by doing this after the call to the configureServices:
                //
                //   services.TryAddSingleton<IUserInfoProvider, FakeUserDatabase>();
                //   services.TryAddSingleton<IWebFrontAuthLoginService, FakeWebFrontAuthLoginService>();
                //
                // Because the CKomposable map needs to see all the services: it locks the ServiceCollections.
                // We only handles the "Fakes" in this overload.
                //
                // Note: IUserInfoProvider and IWebFrontAuthLoginService must obviously be coupled somehow. ISP principle
                //       made us separate the 2 concerns but implementations should be coherent but this cannot be challenged
                //       here (and in a way it shouldn't be).
                //
                if( !map.Services.Mappings.ContainsKey( typeof( IUserInfoProvider ) ) )
                {
                    // Use TryAdd to allow the configureServices function to inject its IUserInfoProvider
                    // if the CKomposable map is missing it.
                    services.TryAddSingleton<IUserInfoProvider, FakeUserDatabase>();
                }
                if( !map.Services.Mappings.ContainsKey( typeof( IWebFrontAuthLoginService ) ) )
                {
                    // Use TryAdd to allow the configureServices function to inject its IWebFrontAuthLoginService
                    // if the CKomposable map is missing it.
                    services.TryAddSingleton<IWebFrontAuthLoginService, FakeWebFrontAuthLoginService>();
                }
                // If the map contains a IUserInfoProvider or a IWebFrontAuthLoginService they will win as they will
                // be the last added.
                services.AddStObjMap( TestHelper.Monitor, map );
            }

            return TestHelper.CreateAspNetAuthServerAsync(
                configureServices: services => ConfigureServices( services, map, configureServices ),
                configureAuth: configureAuth,
                configureApplication: configureApplication,
                webFrontAuthOptions: webFrontAuthOptions );

        }

    }
}
