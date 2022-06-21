using CK.Auth;
using Microsoft.Extensions.Primitives;
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
        public IAuthenticationInfo? Info { get; set; }

        public string? Token { get; set; }

        public bool RememberMe { get; set; }

        public bool Refreshable { get; set; }

        public string[]? Schemes { get; set; }

        public string? Version { get; set; }

        public Dictionary<string, string?>? UserData { get; set; }

        public static RefreshResponse Parse( IAuthenticationTypeSystem t, string json )
        {
            JObject o = JObject.Parse( json );
            var r = new RefreshResponse();
            if( o["info"]?.Type == JTokenType.Object )
            {
                r.Info = t.AuthenticationInfo.FromJObject( (JObject)o["info"]! );
            }
            r.Token = (string?)o["token"];
            r.Refreshable = (bool?)o["refreshable"] ?? false;
            r.RememberMe = (bool?)o["rememberMe"] ?? false;
            r.Schemes = o["schemes"]?.Values<string>().ToArray();
            r.Version = (string?)o["version"];
            var d = o["userData"];
            if( d != null )
            {
                var values = new Dictionary<string, string?>();
                var uD = (JObject)d;
                foreach( var kv in uD )
                {
                    values.Add( kv.Key, (string?)kv.Value );
                }
                r.UserData = values;
            }
            return r;
        }
    }

}
