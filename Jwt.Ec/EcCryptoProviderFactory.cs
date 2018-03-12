using System;
using System.Linq;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto.Parameters;

namespace Jwt.Ec
{
    public class EcCryptoProviderFactory : CryptoProviderFactory
    {
        readonly ECDomainParameters domainParameters;
        readonly string[] supportedAlgorithms;

        public EcCryptoProviderFactory(ECDomainParameters domainParameters, string[] supportedAlgorithms)
        {
            this.domainParameters = domainParameters;
            this.supportedAlgorithms = supportedAlgorithms;
        }

        public override SignatureProvider CreateForSigning(SecurityKey key, string algorithm)
        {
            return new EcSignatureProvider(key, algorithm, domainParameters);
        }

        public override SignatureProvider CreateForVerifying(SecurityKey key, string algorithm)
        {
            return new EcSignatureProvider(key, algorithm, domainParameters);
        }

        public override bool IsSupportedAlgorithm(string algorithm, SecurityKey key)
        {
            return supportedAlgorithms.Any(x => x.Equals(algorithm, StringComparison.OrdinalIgnoreCase)) && key is EcSecurityKey;
        }
    }
}