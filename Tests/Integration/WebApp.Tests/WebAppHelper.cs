using CK.AspNet.Tester;
using CK.Auth;
using CK.Core;
using NUnit.Framework;
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
    [SetUpFixture]
    public class GlobalTeardown
    {
        [TearDown]
        public void StopServers()
        {
            WebAppHelper.WebAppProcess.StopAndWaitForExit();
            WebAppHelper.IdServerProcess.StopAndWaitForExit();
        }
    }

    static class WebAppHelper
    {
        static TestClient _client;

        public static ExternalProcess WebAppProcess = new ExternalProcess(
            pI =>
            {
                var workingDir = Path.Combine( TestHelper.SolutionFolder, "Tests", "Integration", "WebApp" );
                pI.WorkingDirectory = workingDir;
                pI.FileName = Path.Combine( workingDir, "bin", TestHelper.BuildConfiguration, "net461", "WebApp.exe" );
                pI.CreateNoWindow = true;
                pI.UseShellExecute = false;
            },
            p =>
            {
                if( _client != null ) _client.Get( "/quit" );
            } );

        public static ExternalProcess IdServerProcess = new ExternalProcess(
            pI =>
            {
                pI.WorkingDirectory = Path.Combine( TestHelper.SolutionFolder, "Tests", "Integration", "IdServer" );
                pI.FileName = "dotnet";
                pI.Arguments = '"' + Path.Combine( "bin", TestHelper.BuildConfiguration, "netcoreapp1.1", "IdServer.dll" );
                pI.CreateNoWindow = true;
                pI.UseShellExecute = false;
            } );

        static public async Task<TestClient> GetRunningTestClient()
        {
            if( _client == null )
            {
                _client = new TestClient( "http://localhost:4324/" );
            }
            WebAppProcess.EnsureRunning();
            IdServerProcess.EnsureRunning();
            await WaitForWebAppAnswer();
            return _client;
        }

        static async Task WaitForWebAppAnswer()
        {
            int retryCount = 0;
            for(; ; )
            {
                    try
                    {
                        using( HttpResponseMessage msg = await _client.Get( "/test" ) )
                        {
                            if( msg.IsSuccessStatusCode )
                            {
                                string answer = await msg.Content.ReadAsStringAsync();
                                if( answer.Contains( "IAmHere" ) ) break;
                            }
                        }
                    }
                    catch( Exception ex )
                    {
                        TestHelper.Monitor.Warn( $"Failed to connect to WebApp ({++retryCount}).", ex );
                        if( retryCount == 10 ) break;
                        await Task.Delay( 100 );
                    }
                }
            }
        }

        static public readonly IAuthenticationTypeSystem AuthTypeSystem = new StdAuthenticationTypeSystem();

    }
}
