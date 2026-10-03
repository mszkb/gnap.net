using System.Security.Cryptography;
using Gnap.Core.Keys;

namespace Gnap.Interop.Tests;

internal static class TestKeys
{
    /// <summary>A fresh Ed25519 key pair as a private JWK (RFC 8037).</summary>
    public static JsonWebKey NewEd25519(string kid)
    {
        var privateKey = RandomNumberGenerator.GetBytes(32);
        var publicKey = new byte[32];
        Org.BouncyCastle.Math.EC.Rfc8032.Ed25519.GeneratePublicKey(privateKey, 0, publicKey, 0);
        return JsonWebKey.FromEd25519(publicKey, privateKey, kid);
    }

    /// <summary>A fresh ECDSA P-256 key pair as a private JWK.</summary>
    public static JsonWebKey NewP256(string kid)
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return JsonWebKey.FromECDsa(ecdsa, includePrivateKey: true, keyId: kid);
    }
}
