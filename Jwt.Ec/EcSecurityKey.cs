using System;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto.Parameters;

namespace Jwt.Ec
{
    public class EcSecurityKey : SecurityKey
    {
        internal readonly ECPrivateKeyParameters PrivateKeyParameters;
        internal readonly ECPublicKeyParameters PublicKeyParameters;

        public EcSecurityKey(ECPrivateKeyParameters eCPrivateKey)
        {
            PrivateKeyParameters = eCPrivateKey;
        }

        public EcSecurityKey(ECPublicKeyParameters publicKey)
        {
            PublicKeyParameters = publicKey;
        }

        public override int KeySize
        {
            get
            {
                return PrivateKeyParameters.D.BitCount;
            }
        }
    }
}
