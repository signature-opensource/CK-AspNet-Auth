using CK.AspNet.Auth;
using CK.Core;
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;

namespace CK.DB.AspNet.Auth.Tests
{
    class BasicDirectLoginAllower : IWebFrontAuthUnsafeDirectLoginAllowService
    {
        public Task<bool> AllowAsync( HttpContext ctx, IActivityMonitor monitor, string scheme, object payload )
        {
            return Task.FromResult( scheme == "Basic" );
        }
    }

}
