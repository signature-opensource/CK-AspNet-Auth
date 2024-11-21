using CK.Core;
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;

namespace CK.AspNet.Auth.Tests;

class AllDirectLoginAllower : IWebFrontAuthUnsafeDirectLoginAllowService
{
    public Task<bool> AllowAsync( HttpContext ctx, IActivityMonitor monitor, string scheme, object payload ) => Task.FromResult( true );
}
