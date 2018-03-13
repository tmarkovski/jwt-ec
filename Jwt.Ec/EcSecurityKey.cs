using System;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto.Parameters;

namespace Jwt.Ec
{
    public class EcSecurityKey : AsymmetricSecurityKey
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

        public override int KeySize => PrivateKeyParameters.D.BitCount;

        [Obsolete("HasPrivateKey method is deprecated, please use FoundPrivateKey instead.")]
        public override bool HasPrivateKey => PrivateKeyParameters != null;

        public override PrivateKeyStatus PrivateKeyStatus => PrivateKeyParameters != null ? PrivateKeyStatus.Exists : PrivateKeyStatus.DoesNotExist;
    }
}
