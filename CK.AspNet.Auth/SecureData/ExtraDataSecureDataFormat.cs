using CK.Auth;
using CK.Core;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace CK.AspNet.Auth
{
    /// <summary>
    /// Secure IQueryCollection and/or IFormCollection data serialization, using a binary serialization.
    /// </summary>
    public class ExtraDataSecureDataFormat : SecureDataFormat<IDictionary<string, string?>>
    {
        class Serializer : IDataSerializer<IDictionary<string, string?>>
        {
            public IDictionary<string, string?> Deserialize(byte[] data)
            {
                var result = new Dictionary<string, string?>();
                using (var s = new MemoryStream(data))
                using (var r = new CKBinaryReader(s))
                {
                    int c = r.ReadNonNegativeSmallInt32();
                    while( --c >= 0 )
                    {
                        result.Add( r.ReadString(), r.ReadNullableString() );
                    }
                    return result;
                }
            }
            public byte[] Serialize( IDictionary<string, string?> model )
            {
                using (var s = new MemoryStream())
                using (var w = new CKBinaryWriter(s))
                {
                    w.WriteNonNegativeSmallInt32( model.Count );
                    foreach( var k in model )
                    {
                        w.Write( k.Key );
                        w.WriteNullableString( k.Value );
                    }
                    return s.ToArray();
                }
            }
        }

        static readonly Serializer _serializer = new Serializer();

        /// <summary>
        /// Initialize a new AuthenticationInfoSecureDataFormat.
        /// </summary>
        /// <param name="p">Data protector to use.</param>
        public ExtraDataSecureDataFormat( IDataProtector p )
            : base( _serializer, p )
        {
        }
    }

}
