using Gnap.Core;
using Xunit;

namespace Gnap.Core.Tests;

public class InteractionFinishHashTests
{
    // The worked example of RFC 9635 Section 4.2.3.
    private const string ClientNonce = "VJLO6A4CATR0KRO";
    private const string AsNonce = "MBDOFXG4Y5CVJCX821LH";
    private const string InteractRef = "4IFWWIKYB2PQ6U56NL1";
    private const string GrantEndpoint = "https://server.example.com/tx";
    private const string Sha256Hash = "x-gguKWTj8rQf7d7i3w3UhzvuJ5bpOlKyAlVpLxBffY";

    [Fact]
    public void Sha256_MatchesSpecVector()
    {
        Assert.Equal(Sha256Hash, InteractionFinishHash.Compute(ClientNonce, AsNonce, InteractRef, GrantEndpoint, "sha-256"));
    }

    [Fact]
    public void DefaultHashMethod_IsSha256()
    {
        Assert.Equal(Sha256Hash, InteractionFinishHash.Compute(ClientNonce, AsNonce, InteractRef, GrantEndpoint));
    }

    [Fact]
    public void Sha3_512_MatchesSpecVector()
    {
        if (!InteractionFinishHash.IsSupported("sha3-512"))
        {
            return; // SHA-3 is unavailable on this platform; nothing to verify.
        }

        Assert.Equal(
            "pyUkVJSmpqSJMaDYsk5G8WCvgY91l-agUPe1wgn-cc5rUtN69gPI2-S_s-Eswed8iB4PJ_a5Hg6DNi7qGgKwSQ",
            InteractionFinishHash.Compute(ClientNonce, AsNonce, InteractRef, GrantEndpoint, "sha3-512"));
    }

    [Fact]
    public void Verify_AcceptsCorrectHash()
    {
        Assert.True(InteractionFinishHash.Verify(Sha256Hash, ClientNonce, AsNonce, InteractRef, GrantEndpoint));
    }

    [Theory]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")] // wrong value
    [InlineData("")] // empty
    [InlineData("x-gguKWTj8rQf7d7i3w3UhzvuJ5bpOlKyAlVpLxBff")] // truncated
    public void Verify_RejectsWrongHash(string received)
    {
        Assert.False(InteractionFinishHash.Verify(received, ClientNonce, AsNonce, InteractRef, GrantEndpoint));
    }

    [Fact]
    public void Verify_RejectsSwappedNonces()
    {
        Assert.False(InteractionFinishHash.Verify(Sha256Hash, AsNonce, ClientNonce, InteractRef, GrantEndpoint));
    }

    [Fact]
    public void Verify_RejectsDifferentEndpoint()
    {
        Assert.False(InteractionFinishHash.Verify(Sha256Hash, ClientNonce, AsNonce, InteractRef, "https://attacker.example/tx"));
    }

    [Fact]
    public void UnknownHashMethod_Throws()
    {
        Assert.Throws<GnapException>(() =>
            InteractionFinishHash.Compute(ClientNonce, AsNonce, InteractRef, GrantEndpoint, "md5"));
    }

    [Fact]
    public void Verify_UnknownHashMethod_ReturnsFalse()
    {
        Assert.False(InteractionFinishHash.Verify(Sha256Hash, ClientNonce, AsNonce, InteractRef, GrantEndpoint, "md5"));
    }

    [Theory]
    [InlineData("sha-384")]
    [InlineData("sha-512")]
    public void OtherSha2Methods_RoundTrip(string method)
    {
        var hash = InteractionFinishHash.Compute(ClientNonce, AsNonce, InteractRef, GrantEndpoint, method);
        Assert.True(InteractionFinishHash.Verify(hash, ClientNonce, AsNonce, InteractRef, GrantEndpoint, method));
        Assert.NotEqual(Sha256Hash, hash);
    }
}
