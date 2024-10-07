using Newtonsoft.Json.Linq;

namespace CK.Testing;

/// <summary>
/// Captures the authentication cookie values.
/// </summary>
/// <param name="AuthCookie"></param>
/// <param name="LTCookie"></param>
/// <param name="LTDeviceId"></param>
/// <param name="LTUserId"></param>
/// <param name="LTUserName"></param>
public record struct AuthenticationCookieValues( string? AuthCookie, JObject? LTCookie, string? LTDeviceId, string? LTUserId, string? LTUserName )
{
    public static implicit operator (string? AuthCookie, JObject? LTCookie, string? LTDeviceId, string? LTUserId, string? LTUserName)( AuthenticationCookieValues value )
    {
        return (value.AuthCookie, value.LTCookie, value.LTDeviceId, value.LTUserId, value.LTUserName);
    }

    public static implicit operator AuthenticationCookieValues( (string? AuthCookie, JObject? LTCookie, string? LTDeviceId, string? LTUserId, string? LTUserName) value )
    {
        return new AuthenticationCookieValues( value.AuthCookie, value.LTCookie, value.LTDeviceId, value.LTUserId, value.LTUserName );
    }
}
