using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting;
using System.Threading;

namespace IdServer
{
    public class Program
    {
        public static void Main( string[] args )
        {
            bool createdNew;
            using( Mutex m = new Mutex( true, "Invenietis.CK.AspNet.Auth.Integration.IdServer", out createdNew ) )
            {
                if( createdNew )
                {
                    var host = new WebHostBuilder()
                .UseKestrel()
                .UseContentRoot( Directory.GetCurrentDirectory() )
                .UseIISIntegration()
                .UseStartup<Startup>()
                .Build();

                    host.Run();
                }
            }
        }
    }
}
