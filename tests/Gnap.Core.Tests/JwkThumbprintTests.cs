using Gnap.Core;
using Gnap.Core.Keys;
using Xunit;

namespace Gnap.Core.Tests;

public class JwkThumbprintTests
{
    // RFC 7638 Section 3.1: the specification's RSA example key and thumbprint.
    [Fact]
    public void RsaThumbprint_MatchesRfc7638Vector()
    {
        var jwk = new JsonWebKey
        {
            Kty = "RSA",
            N = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            E = "AQAB",
            Alg = "RS256",
            Kid = "2011-04-29",
        };

        Assert.Equal("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", jwk.ComputeThumbprint());
    }

    // RFC 8037 Appendix A.3: Ed25519 OKP thumbprint.
    [Fact]
    public void Ed25519Thumbprint_MatchesRfc8037Vector()
    {
        var jwk = new JsonWebKey
        {
            Kty = "OKP",
            Crv = "Ed25519",
            X = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
        };

        Assert.Equal("kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k", jwk.ComputeThumbprint());
    }

    [Fact]
    public void Thumbprint_IgnoresOptionalMembers()
    {
        var bare = new JsonWebKey { Kty = "OKP", Crv = "Ed25519", X = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" };
        var decorated = new JsonWebKey
        {
            Kty = "OKP",
            Crv = "Ed25519",
            X = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
            Kid = "my-key",
            Alg = "EdDSA",
            Use = "sig",
        };

        Assert.Equal(bare.ComputeThumbprint(), decorated.ComputeThumbprint());
    }

    [Fact]
    public void Thumbprint_SameForPublicAndPrivateKey()
    {
        using var ecdsa = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        var withPrivate = JsonWebKey.FromECDsa(ecdsa, includePrivateKey: true);
        var publicOnly = JsonWebKey.FromECDsa(ecdsa);

        Assert.Equal(publicOnly.ComputeThumbprint(), withPrivate.ComputeThumbprint());
    }

    [Fact]
    public void Thumbprint_MissingRequiredMember_Throws()
    {
        var jwk = new JsonWebKey { Kty = "RSA", E = "AQAB" };
        Assert.Throws<GnapException>(jwk.ComputeThumbprint);
    }

    [Fact]
    public void Thumbprint_UnknownKeyType_Throws()
    {
        var jwk = new JsonWebKey { Kty = "XYZ" };
        Assert.Throws<GnapException>(jwk.ComputeThumbprint);
    }
}
