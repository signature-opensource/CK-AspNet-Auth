using CK.Auth;
using CK.Core;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace CK.AspNet.Auth;

/// <summary>
/// Secure <see cref="FrontAuthenticationInfo"/> data, using a binary serialization 
/// thanks to <see cref="IAuthenticationTypeSystem"/>.
/// </summary>
class FrontAuthenticationInfoSecureDataFormat : SecureDataFormat<FrontAuthenticationInfo>
{
    class Serializer : IDataSerializer<FrontAuthenticationInfo>
    {
        readonly IAuthenticationInfoType _t;

        public Serializer( IAuthenticationTypeSystem t )
        {
            _t = t.AuthenticationInfo;
        }

        public FrontAuthenticationInfo Deserialize( byte[] data )
        {
            using( var s = Util.RecyclableStreamManager.GetStream( data ) )
            using( var r = new BinaryReader( s ) )
            {
                return new FrontAuthenticationInfo( _t.Read( r )!, r.ReadBoolean() );
            }
        }

        public byte[] Serialize( FrontAuthenticationInfo model )
        {
            using( var s = Util.RecyclableStreamManager.GetStream() )
            using( var w = new BinaryWriter( s ) )
            {
                _t.Write( w, model.Info );
                w.Write( model.RememberMe );
                return s.ToArray();
            }
        }
    }

    /// <summary>
    /// Initialize a new AuthenticationInfoSecureDataFormat.
    /// </summary>
    /// <param name="t">Type system to use.</param>
    /// <param name="p">Data protector to use.</param>
    public FrontAuthenticationInfoSecureDataFormat( IAuthenticationTypeSystem t, IDataProtector p )
        : base( new Serializer( t ), p )

    {
    }
}
