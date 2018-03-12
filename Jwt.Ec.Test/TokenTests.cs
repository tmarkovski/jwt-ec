using System;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Xunit;
using Jwt.Ec;
using System.Linq;

namespace Jwt.Ec.Test
{
    public class TokenTests
    {
        X9ECParameters secp256k1;
        ECDomainParameters domainParams;
        string algorithm = "ES256K";
        DateTime now = DateTime.Now;

        public TokenTests()
        {
            secp256k1 = ECNamedCurveTable.GetByName("secp256k1");
            domainParams = new ECDomainParameters(secp256k1.Curve, secp256k1.G, secp256k1.N, secp256k1.H);
        }

        [Fact]
        public void Generate_Secp256k1_SignedToken()
        {
            var privateKey = GeneratePrivateKey(domainParams);
            var securityKey = new EcSecurityKey(privateKey);

            var signingCredentials = new SigningCredentials(securityKey, algorithm);
            signingCredentials.CryptoProviderFactory = new EcCryptoProviderFactory(domainParams, new[] { algorithm });

            var tokenHandler = new JwtSecurityTokenHandler();
            var jwtToken = tokenHandler.CreateJwtSecurityToken(
                issuer: "me",
                audience: "you",
                subject: null,
                notBefore: now,
                expires: now.AddMinutes(30),
                issuedAt: now,
                signingCredentials: signingCredentials);

            var token = tokenHandler.WriteToken(jwtToken);

            Assert.NotNull(token);
            Assert.Equal(3, token.Split(".").Length);
        }

        [Fact]
        public void Verify_Signature()
        {
            var privateKey = GeneratePrivateKey(domainParams);

            var signingCredentials = new SigningCredentials(new EcSecurityKey(privateKey), algorithm);
            signingCredentials.CryptoProviderFactory = new EcCryptoProviderFactory(domainParams, new[] { algorithm });

            var tokenHandler = new JwtSecurityTokenHandler();
            var jwtToken = tokenHandler.CreateJwtSecurityToken(
                issuer: "me",
                audience: "you",
                subject: null,
                notBefore: now,
                expires: now.AddMinutes(30),
                issuedAt: now,
                signingCredentials: signingCredentials);

            var token = tokenHandler.WriteToken(jwtToken);

            // Verify
            var publicKey = new EcSecurityKey(new ECPublicKeyParameters(domainParams.G.Multiply(privateKey.D), domainParams));
            tokenHandler = new JwtSecurityTokenHandler();

            var settings = new TokenValidationParameters()
            {
                ValidIssuer = "me",
                ValidAudience = "you",
                IssuerSigningKey = publicKey,
                CryptoProviderFactory = new EcCryptoProviderFactory(domainParams, new[] { algorithm })
            };

            var claims = tokenHandler.ValidateToken(token, settings, out var securityToken);

            Assert.NotNull(claims);
        }

        static ECPrivateKeyParameters GeneratePrivateKey(ECDomainParameters domainParams)
        {
            var keyParams = new ECKeyGenerationParameters(domainParams, new SecureRandom());

            var generator = new ECKeyPairGenerator("ECDSA");
            generator.Init(keyParams);

            var keyPair = generator.GenerateKeyPair();
            return (keyPair.Private as ECPrivateKeyParameters);
        }
    }
}