using CK.Auth;
using CK.Core;
using CK.DB.Auth;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace CK.AspNet.AuthService.Tests
{
    class AuthServer : IDisposable
    {
        IAuthenticationDatabaseService _dbAuthService;
        IAuthenticationTypeSystem _typeSystem;

        public AuthServer(WebFrontAuthMiddlewareOptions options, IAuthenticationDatabaseService authService = null)
        {
            Options = options;
            _dbAuthService = authService;
            _typeSystem = new TestAuthenticationTypeSystem();
            var b = WebHostBuilderFactory.Create(null, null, StandardConfigureServices, app =>
            {
               app.UseWebFrontAuth(options);
            });
            Server = new TestServer(b);
            Client = new TestClient(Server);
        }

        public IAuthenticationDatabaseService AuthService => _dbAuthService;

        public IAuthenticationTypeSystem TypeSystem => _typeSystem;

        public WebFrontAuthMiddlewareOptions Options { get; }

        public TestServer Server { get; }

        public TestClient Client { get; }

        void StandardConfigureServices(IServiceCollection services)
        {
            services.AddSingleton(_typeSystem);
            if (_dbAuthService == null)
            {
                foreach (var kv in TestHelper.StObjMap.Default.Mappings)
                {
                    services.AddSingleton(kv.Key, kv.Value);
                    if (kv.Key == typeof(IAuthenticationDatabaseService))
                    {
                        _dbAuthService = (IAuthenticationDatabaseService)kv.Value;
                    }
                }
            }
            else services.AddSingleton(_dbAuthService);
            services.AddWebFrontAuth();
        }

        public void Dispose()
        {
            Server?.Dispose();
        }
    }

}
