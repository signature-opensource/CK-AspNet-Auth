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

        public List<KeyValuePair<string, StringValues>>? UserData { get; set; }

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
                var values = new List<KeyValuePair<string,StringValues>>();
                var uD = (JObject)d;
                foreach( var kv in uD )
                {
                    StringValues v; 
                    if( kv.Value == null ) v = StringValues.Empty;
                    else if( kv.Value is JArray a ) v = new StringValues( a.Select( c => (string)c ).ToArray() );
                    else v = new StringValues( (string)kv.Value );
                    values.Add( KeyValuePair.Create( kv.Key, v ) );
                }
                r.UserData = values;
            }
            return r;
        }
    }

}
