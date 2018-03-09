using System;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto.Parameters;

namespace Jwt.Extensions
{
    public class EcCryptoProviderFactory : CryptoProviderFactory
    {
        readonly ECDomainParameters domainParameters;

        public EcCryptoProviderFactory(ECDomainParameters domainParameters)
        {
            this.domainParameters = domainParameters;
        }

        public override SignatureProvider CreateForSigning(SecurityKey key, string algorithm)
        {
            return new EcSignatureProvider(key, algorithm, domainParameters);
        }

        public override SignatureProvider CreateForVerifying(SecurityKey key, string algorithm)
        {
            return base.CreateForVerifying(key, algorithm);
        }

        public override bool IsSupportedAlgorithm(string algorithm, SecurityKey key)
        {
            return base.IsSupportedAlgorithm(algorithm, key);
        }

        public override bool IsSupportedAlgorithm(string algorithm)
        {
            return base.IsSupportedAlgorithm(algorithm);
        }
    }
}