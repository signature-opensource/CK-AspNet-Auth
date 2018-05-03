using CK.Auth;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WebApp.Tests
{
    public class LoginResponse : RefreshResponse
    {
        public string LoginFailureReason { get; set; }

        public int LoginFailureCode { get; set; }

        public static new LoginResponse Parse( IAuthenticationTypeSystem t, string json )
        {
            var r = new LoginResponse();
            r.DoParse( t, JObject.Parse( json ) );
            return r;
        }

        protected override void DoParse( IAuthenticationTypeSystem t, JObject o )
        {
            base.DoParse( t, o );
            LoginFailureReason = (string)o["loginFailureReason"];
            LoginFailureCode = (int?)o["loginFailureCode"] ?? 0;
        }
    }

}
