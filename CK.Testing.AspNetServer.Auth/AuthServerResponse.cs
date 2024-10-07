using CK.Auth;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CK.Testing;

/// <summary>
/// Models the response of the authentication server.
/// </summary>
public sealed class AuthServerResponse
{
    /// <summary>
    /// Gets the authentication info.
    /// </summary>
    public IAuthenticationInfo? Info { get; set; }

    /// <summary>
    /// Gets the token.
    /// </summary>
    public string? Token { get; set; }

    public bool RememberMe { get; set; }

    public bool Refreshable { get; set; }

    public string? ErrorId { get; set; }

    public string? ErrorText { get; set; }

    public string?[]? Schemes { get; set; }

    public string? Version { get; set; }

    public IList<(string, string?)> UserData { get; } = new List<(string, string?)>();

    /// <summary>
    /// Parse a server response.
    /// </summary>
    /// <param name="t">The type system.</param>
    /// <param name="json">The json string.</param>
    /// <returns>The server response.</returns>
    public static AuthServerResponse Parse( IAuthenticationTypeSystem t, string json )
    {
        JObject o = JObject.Parse( json );
        var r = new AuthServerResponse();
        if( o["info"]?.Type == JTokenType.Object )
        {
            r.Info = t.AuthenticationInfo.FromJObject( (JObject)o["info"]! );
        }
        r.Token = (string?)o["token"];
        r.Refreshable = (bool?)o["refreshable"] ?? false;
        r.RememberMe = (bool?)o["rememberMe"] ?? false;
        r.Schemes = o["schemes"]?.Values<string>().ToArray();
        r.Version = (string?)o["version"];
        var userData = (JObject?)o["userData"];
        if( userData != null )
        {
            foreach( var kv in userData )
            {
                r.UserData.Add( (kv.Key, (string?)kv.Value) );
            }
        }
        r.ErrorId = (string?)o["errorId"];
        r.ErrorText = (string?)o["errorText"];
        return r;
    }
}
