using CK.AspNet.Tester;
using CK.Auth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using System;

namespace CK.AspNet.Auth.Tests
{
    class AuthServer : IDisposable
    {
        IAuthenticationTypeSystem _typeSystem;
        WebFrontAuthService _authService;

        public AuthServer(
            WebFrontAuthMiddlewareOptions options, 
            Action<IServiceCollection> configureServices = null,
            Action<IApplicationBuilder> configureApplication = null )
        {
            Options = options;
            var b = WebHostBuilderFactory.Create(null, null, 
                services =>
                {
                    services.AddAuthentication();
                    services.AddSingleton<IAuthenticationTypeSystem,StdAuthenticationTypeSystem>();
                    services.AddSingleton<WebFrontAuthService,FakeWebFrontService>();
                    configureServices?.Invoke(services);
                },
                app =>
                {
                    _typeSystem = (IAuthenticationTypeSystem)app.ApplicationServices.GetService(typeof(IAuthenticationTypeSystem));
                    _authService = (WebFrontAuthService)app.ApplicationServices.GetService(typeof(WebFrontAuthService));
                    app.UseWebFrontAuth(options);
                    configureApplication?.Invoke(app);
                });
            Server = new TestServer(b);
            Client = new TestClient(Server);
        }

        public WebFrontAuthService AuthService => _authService;

        public IAuthenticationTypeSystem TypeSystem => _typeSystem;

        public WebFrontAuthMiddlewareOptions Options { get; }

        public TestServer Server { get; }

        public TestClient Client { get; }

        public void Dispose()
        {
            Server?.Dispose();
        }

    }

}
