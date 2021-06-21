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
    public class ExtraDataSecureDataFormat : SecureDataFormat<IEnumerable<KeyValuePair<string, StringValues>>>
    {
        class Serializer : IDataSerializer<IEnumerable<KeyValuePair<string, StringValues>>>
        {
            public IEnumerable<KeyValuePair<string, StringValues>> Deserialize(byte[] data)
            {
                var result = new List<KeyValuePair<string, StringValues>>();
                using (var s = new MemoryStream(data))
                using (var r = new CKBinaryReader(s))
                {
                    string? key;
                    while( (key = r.ReadNullableString()) != null )
                    {
                        var values = new string[r.ReadSmallInt32()];
                        for(int i = 0; i < values.Length; ++i )
                        {
                            // If the value was null, we restore a null.
                            values[i] = r.ReadNullableString()!;
                        }
                        result.Add( new KeyValuePair<string, StringValues>( key, new StringValues( values ) ) );
                    }
                    return result;
                }
            }
            public byte[] Serialize( IEnumerable<KeyValuePair<string, StringValues>> model )
            {
                using (var s = new MemoryStream())
                using (var w = new CKBinaryWriter(s))
                {
                    foreach( var k in model )
                    {
                        if( k.Key == null ) throw new InvalidDataException( "Key can not be null." );
                        w.WriteNullableString( k.Key );
                        w.WriteSmallInt32( k.Value.Count );
                        foreach( var v in k.Value )
                        {
                            w.WriteNullableString( v );
                        }
                    }
                    w.WriteNullableString( null );
                    return s.ToArray();
                }
            }
        }

        /// <summary>
        /// Initialize a new AuthenticationInfoSecureDataFormat.
        /// </summary>
        /// <param name="p">Data protector to use.</param>
        public ExtraDataSecureDataFormat( IDataProtector p )
            : base( new Serializer(), p )
        {
        }
    }

}
