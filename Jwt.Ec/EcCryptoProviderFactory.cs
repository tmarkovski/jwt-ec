using System;
using System.Linq;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace Jwt.Ec
{
    public class EcCryptoProviderFactory : CryptoProviderFactory
    {
        readonly ECDomainParameters domainParameters;
        readonly string[] supportedAlgorithms;
        readonly bool deterministic;
        readonly IDigest digest;

        public EcCryptoProviderFactory(ECDomainParameters domainParameters, string[] supportedAlgorithms, bool deterministic = false, IDigest digest = null)
        {
            this.digest = digest;
            this.deterministic = deterministic;
            this.domainParameters = domainParameters;
            this.supportedAlgorithms = supportedAlgorithms;
        }

        public override SignatureProvider CreateForSigning(SecurityKey key, string algorithm)
        {
            return new EcSignatureProvider(key, algorithm, domainParameters, deterministic, digest);
        }

        public override SignatureProvider CreateForVerifying(SecurityKey key, string algorithm)
        {
            return new EcSignatureProvider(key, algorithm, domainParameters, deterministic, digest);
        }

        public override bool IsSupportedAlgorithm(string algorithm, SecurityKey key)
        {
            return supportedAlgorithms.Any(x => x.Equals(algorithm, StringComparison.OrdinalIgnoreCase)) && key is EcSecurityKey;
        }
    }
}