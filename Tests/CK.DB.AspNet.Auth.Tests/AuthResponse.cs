using CK.Auth;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CK.DB.AspNet.Auth.Tests
{
    class AuthResponse
    {
        public IAuthenticationInfo? Info { get; set; }

        public string? Token { get; set; }

        public bool? Refreshable { get; set; }

        public IList<KeyValuePair<string, string>> UserData { get; } = new List<KeyValuePair<string, string>>();

        public string? ErrorId { get; set; }

        public string? ErrorText { get; set; }

        public static AuthResponse Parse( IAuthenticationTypeSystem t, string json )
        {
            JObject o = JObject.Parse( json );
            var r = new AuthResponse();
            if( o["info"]?.Type == JTokenType.Object )
            {
                r.Info = t.AuthenticationInfo.FromJObject( (JObject?)o["info"] );
            }
            r.Token = (string?)o["token"];
            r.Refreshable = (bool?)o["refreshable"];
            var userData = (JObject?)o["userData"];
            if( userData != null )
            {
                foreach( var kv in userData )
                {
                    r.UserData.Add( new KeyValuePair<string, string>( kv.Key, (string)kv.Value! ) );
                }
            }
            r.ErrorId = (string?)o["errorId"];
            r.ErrorText = (string?)o["errorText"];
            return r;
        }
    }

}
