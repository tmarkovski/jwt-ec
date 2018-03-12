using System;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;

namespace Jwt.Ec
{
    public class EcSignatureProvider : SignatureProvider
    {
        readonly ECDomainParameters DomainParams;

        public EcSignatureProvider(SecurityKey key, string algorithm, ECDomainParameters domainParameters)
            : base(key, algorithm)
        {
            DomainParams = domainParameters;
        }

        public override byte[] Sign(byte[] input)
        {
            var key = Key as EcSecurityKey;
            if (key == null || key.PrivateKeyParameters == null) throw new ArgumentException("Private Key must be of type EcSecurityKey and be initialized");

            var signer = new ECDsaSigner(new HMacDsaKCalculator(new Sha256Digest()));
            signer.Init(true, key.PrivateKeyParameters);
            var signature = signer.GenerateSignature(input);

            var R = signature[0];
            var S = signature[1];

            //// Ensure low S
            //if (!(S.CompareTo(DomainParams.N.ShiftRight(1)) <= 0))
            //{
            //    S = DomainParams.N.Subtract(S);
            //}

            return R.ToByteArrayUnsigned().Concat(S.ToByteArrayUnsigned()).ToArray();
        }

        public override bool Verify(byte[] input, byte[] signature)
        {
            var key = Key as EcSecurityKey;
            if (key == null || key.PublicKeyParameters == null) throw new ArgumentException("Public Key must be of type EcSecurityKey and be initialized");

            var R = new BigInteger(1, signature.Take(32).ToArray());
            var S = new BigInteger(1, signature.Skip(32).ToArray());

            var signer = new ECDsaSigner(new HMacDsaKCalculator(new Sha256Digest()));
            signer.Init(false, key.PublicKeyParameters);
            var result = signer.VerifySignature(input, R, S);

            return result;
        }

        protected override void Dispose(bool disposing)
        {
        }
    }
}
