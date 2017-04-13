using CK.Auth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace CK.AspNet.AuthService
{
    class AuthenticationInfoSecureDataFormat : SecureDataFormat<IAuthenticationInfo>
    {
        class Serializer : IDataSerializer<IAuthenticationInfo>
        {
            readonly IAuthenticationInfoType _t;

            public Serializer(IAuthenticationTypeSystem t)
            {
                _t = t.AuthenticationInfo;
            }

            public IAuthenticationInfo Deserialize(byte[] data)
            {
                using (var s = new MemoryStream(data))
                using (var r = new BinaryReader(s))
                {
                    return _t.Read(r);
                }
            }
            public byte[] Serialize(IAuthenticationInfo model)
            {
                using (var s = new MemoryStream())
                using (var w = new BinaryWriter(s))
                {
                    _t.Write(w, model);
                    return s.ToArray();
                }
            }
        }

        public AuthenticationInfoSecureDataFormat(IAuthenticationTypeSystem t, IDataProtector p)
            : base(new Serializer(t), p)

        {
        }
    }

}
