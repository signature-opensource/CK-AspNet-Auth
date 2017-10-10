using CK.AspNet.Tester;
using CK.Auth;
using CK.Core;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace WebApp.Tests
{
    static class WebAppHelper
    {
        static TestClient _client;

        static public async Task<TestClient> GetRunningTestClient()
        {
            if( _client == null )
            {
                // This ensures that the generated dll exists.
                // WebApp references our WebApp.Tests.Generated dll.
                var stObjMap = TestHelper.LoadStObjMapFromExistingGeneratedAssembly();
                if( stObjMap == null ) stObjMap = TestHelper.StObjMap;
                LaunchWebApp();
                LaunchIdServer();
                _client = new TestClient( "http://localhost:4324/" );
                int retryCount = 0;
                for( ; ;)
                {
                    using( HttpResponseMessage msg = await _client.Get( "/test" ) )
                    {
                        try
                        {
                            if( msg.IsSuccessStatusCode )
                            {
                                string answer = await msg.Content.ReadAsStringAsync();
                                if( answer.Contains( "IAmHere" ) ) break;
                            }
                        }
                        catch( Exception ex )
                        {
                            TestHelper.Monitor.Warn( $"Failed to connect to WebApp ({++retryCount})." );
                            if( retryCount == 10 ) break;
                            await Task.Delay( 100 );
                        }
                    }
                }
            }
            return _client;
        }

        static void LaunchWebApp()
        {
            var pI = new ProcessStartInfo()
            {
                WorkingDirectory = Path.Combine( TestHelper.SolutionFolder, "Tests", "Integration", "WebApp" ),
                FileName = Path.Combine( "bin", TestHelper.BuildConfiguration, "net461", "WebApp.exe" )
            };
            Process.Start( pI );
        }

        static void LaunchIdServer()
        {
            var pI = new ProcessStartInfo()
            {
                WorkingDirectory = Path.Combine( TestHelper.SolutionFolder, "Tests", "Integration", "IdServer" ),
                FileName = "dotnet",
                Arguments = '"' + Path.Combine( "bin", TestHelper.BuildConfiguration, "netcoreapp1.1", "IdServer.dll" )
            };
            Process.Start( pI );
        }

        static public readonly IAuthenticationTypeSystem AuthTypeSystem = new StdAuthenticationTypeSystem();

    }
}
