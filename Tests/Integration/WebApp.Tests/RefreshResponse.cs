using CK.Auth;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WebApp.Tests
{
    public class RefreshResponse
    {
        public IAuthenticationInfo Info { get; set; }

        public string Token { get; set; }

        public bool Refreshable { get; set; }

        public string[] Schemes { get; set; }

        public static RefreshResponse Parse( IAuthenticationTypeSystem t, string json )
        {
            var r = new RefreshResponse();
            r.DoParse( t, JObject.Parse( json ) );
            return r;
        }

        protected virtual void DoParse( IAuthenticationTypeSystem t, JObject o )
        {
            if( o["info"].Type == JTokenType.Object )
            {
                Info = t.AuthenticationInfo.FromJObject( (JObject)o["info"] );
            }
            Token = (string)o["token"];
            Refreshable = (bool)o["refreshable"];
            Schemes = o["schemes"]?.Values<string>().ToArray();
        }
    }

}
