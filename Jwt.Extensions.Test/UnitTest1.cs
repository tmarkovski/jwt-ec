using System;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Xunit;

namespace Jwt.Extensions.Test
{
    public class UnitTest1
    {
        [Fact]
        public void GenerateSecp256k1_SignedToken()
        {
            var secp256k1 = ECNamedCurveTable.GetByName("secp256k1");
            var DomainParams = new ECDomainParameters(secp256k1.Curve, secp256k1.G, secp256k1.N, secp256k1.H);

            var now = DateTime.Now;
            var tokenHandler = new JwtSecurityTokenHandler();
            var privateKey = GeneratePrivateKey(DomainParams);

            var securityKey = new EcSecurityKey(privateKey);
            var signingCredentials = new SigningCredentials(securityKey, "ECDSA");

            signingCredentials.CryptoProviderFactory = new EcCryptoProviderFactory(DomainParams);

            var jwtToken = tokenHandler.CreateJwtSecurityToken(
                issuer: "me",
                audience: "you",
                subject: null,
                notBefore: now,
                expires: now.AddMinutes(30),
                issuedAt: now,
                signingCredentials: signingCredentials);

            var token = tokenHandler.WriteToken(jwtToken);

            Debug.WriteLine($"Public Key base64 encoded: {GetPublicKeyBase64(DomainParams, privateKey)}");
        }

        public static ECPrivateKeyParameters GeneratePrivateKey(ECDomainParameters domainParams)
        {
            var keyParams = new ECKeyGenerationParameters(domainParams, new SecureRandom());

            var generator = new ECKeyPairGenerator("ECDSA");
            generator.Init(keyParams);

            var keyPair = generator.GenerateKeyPair();
            return (keyPair.Private as ECPrivateKeyParameters);
        }

        public string GetPublicKeyBase64(ECDomainParameters domainParams, ECPrivateKeyParameters privateKey)
        {
            var Q = domainParams.G.Multiply(privateKey.D);
            return Convert.ToBase64String(Q.Normalize().GetEncoded());
        }
    }
}