using NUnitLite;
using System.Globalization;
using System.Reflection;

namespace CK.DB.AspNet.Auth.NetCore.Tests
{
    public static class Program
    {
        public static int Main(string[] args)
        {
            CultureInfo.CurrentCulture
                = CultureInfo.CurrentUICulture
                = CultureInfo.DefaultThreadCurrentCulture
                = CultureInfo.DefaultThreadCurrentUICulture = new CultureInfo( "en-US" );
            return new AutoRun(Assembly.GetEntryAssembly()).Execute(args);
        }
    }
}
