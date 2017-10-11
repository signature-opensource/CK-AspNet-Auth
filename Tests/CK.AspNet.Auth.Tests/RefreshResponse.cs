using CK.Auth;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CK.AspNet.Auth.Tests
{
    class RefreshResponse
    {
        public IAuthenticationInfo Info { get; set; }

        public string Token { get; set; }

        public bool Refreshable { get; set; }

        public string[] Schemes { get; set; }

        public static RefreshResponse Parse( IAuthenticationTypeSystem t, string json )
        {
            JObject o = JObject.Parse( json );
            var r = new RefreshResponse();
            if( o["info"].Type == JTokenType.Object )
            {
                r.Info = t.AuthenticationInfo.FromJObject( (JObject)o["info"] );
            }
            r.Token = (string)o["token"];
            r.Refreshable = (bool)o["refreshable"];
            r.Schemes = o["schemes"]?.Values<string>().ToArray();
            return r;
        }
    }

}
