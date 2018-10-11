using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting;
using System.Threading;
using CK.Monitoring;
using CK.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace WebApp
{
    public class Program
    {
        public static void Main( string[] args )
        {
            var host = new WebHostBuilder()
                .UseUrls( "http://localhost:4324" )
                .UseKestrel()
                .UseContentRoot( Directory.GetCurrentDirectory() )
                .ConfigureLogging( b =>
                {
                    // This has no impact :(
                    // b.SetMinimumLevel( Microsoft.Extensions.Logging.LogLevel.Trace );
                    // Adding the Console, displays the Request start/end. WTF?!
                    b.AddConsole();
                    b.SetMinimumLevel( Microsoft.Extensions.Logging.LogLevel.Trace );
                } )
                .ConfigureAppConfiguration( c => c.AddJsonFile( "appsettings.json", true, true ) )
                .UseMonitoring()
                .UseStartup<Startup>()
                .Build();

            host.Run();
            GrandOutput.Default?.Dispose();
        }
    }
}
