using System;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto.Parameters;

namespace Jwt.Extensions
{
    public class EcSecurityKey : SecurityKey
    {
        internal readonly ECPrivateKeyParameters EcKeyParameters;

        public EcSecurityKey(ECPrivateKeyParameters eCPrivateKey)
        {
            this.EcKeyParameters = eCPrivateKey;
        }

        public override int KeySize => EcKeyParameters.D.BitCount;
    }
}
