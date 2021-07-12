using CK.AspNet.Auth;
using CK.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace CK.DB.AspNet.Auth
{
    public class WebFrontAuthOptionsInstaller : IRealObject
    {
        void ConfigureServices( StObjContextRoot.ServiceRegister reg )
        {
            reg.Services.AddOptions<WebFrontAuthOptions>()
                        .Configure<IConfiguration>( ( opts, config ) => config.GetSection( "CK-WebFrontAuth" ).Bind( opts ) );
            reg.Services.AddSingleton<IOptionsChangeTokenSource<WebFrontAuthOptions>, ConfigurationChangeTokenSource<WebFrontAuthOptions>>();
        }
    }

}
