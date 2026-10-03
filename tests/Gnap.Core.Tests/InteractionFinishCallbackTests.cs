using Gnap.Core.Json;
using Gnap.Core.Models;
using Xunit;

namespace Gnap.Core.Tests;

public class InteractionFinishCallbackTests
{
    // The worked example of RFC 9635 Section 4.2.3.
    private const string ClientNonce = "VJLO6A4CATR0KRO";
    private const string AsNonce = "MBDOFXG4Y5CVJCX821LH";
    private const string InteractRef = "4IFWWIKYB2PQ6U56NL1";
    private const string GrantEndpoint = "https://server.example.com/tx";
    private const string Hash = "x-gguKWTj8rQf7d7i3w3UhzvuJ5bpOlKyAlVpLxBffY";

    [Fact]
    public void RedirectUri_AppendsParameters()
    {
        var callback = new InteractionFinishCallback { Hash = Hash, InteractRef = InteractRef };
        var uri = callback.ToRedirectUri("https://client.example.net/return/123455");

        Assert.Equal(
            $"https://client.example.net/return/123455?hash={Hash}&interact_ref={InteractRef}",
            uri.AbsoluteUri);
    }

    [Fact]
    public void RedirectUri_KeepsExistingQuery()
    {
        var callback = new InteractionFinishCallback { Hash = Hash, InteractRef = InteractRef };
        var uri = callback.ToRedirectUri("https://client.example.net/return?session=abc");

        Assert.StartsWith("https://client.example.net/return?session=abc&hash=", uri.AbsoluteUri, StringComparison.Ordinal);
        Assert.True(InteractionFinishCallback.TryParseRedirectUri(uri, out var parsed));
        Assert.Equal(Hash, parsed.Hash);
        Assert.Equal(InteractRef, parsed.InteractRef);
    }

    [Fact]
    public void RedirectUri_RequiresBothValues()
    {
        Assert.Throws<GnapException>(() => new InteractionFinishCallback { Hash = Hash }.ToRedirectUri("https://c.example/"));
        Assert.Throws<GnapException>(() => new InteractionFinishCallback { Hash = Hash, InteractRef = InteractRef }.ToRedirectUri("/relative"));
    }

    [Theory]
    [InlineData("https://client.example.net/return?hash=abc")]
    [InlineData("https://client.example.net/return?interact_ref=abc")]
    [InlineData("https://client.example.net/return?hash=&interact_ref=abc")]
    [InlineData("https://client.example.net/return?hash=a&hash=b&interact_ref=abc")]
    public void TryParseRedirectUri_RejectsIncompleteOrAmbiguous(string uri)
    {
        Assert.False(InteractionFinishCallback.TryParseRedirectUri(new Uri(uri), out _));
    }

    [Fact]
    public void PushBody_RoundTrips()
    {
        var json = GnapJson.Serialize(new InteractionFinishCallback { Hash = Hash, InteractRef = InteractRef });
        Assert.Equal($$"""{"hash":"{{Hash}}","interact_ref":"{{InteractRef}}"}""", json);

        var parsed = GnapJson.DeserializeFinishCallback(/*lang=json,strict*/ """
            {"hash":"x-gguKWTj8rQf7d7i3w3UhzvuJ5bpOlKyAlVpLxBffY","interact_ref":"4IFWWIKYB2PQ6U56NL1","future":1}
            """)!;
        Assert.Equal(Hash, parsed.Hash);
        Assert.Equal(InteractRef, parsed.InteractRef);
    }

    [Fact]
    public void VerifyHash_UsesSpecVector()
    {
        var callback = new InteractionFinishCallback { Hash = Hash, InteractRef = InteractRef };
        Assert.True(callback.VerifyHash(ClientNonce, AsNonce, GrantEndpoint));
        Assert.False(callback.VerifyHash(AsNonce, ClientNonce, GrantEndpoint));

        var forged = new InteractionFinishCallback { Hash = Hash, InteractRef = "OTHER-REF" };
        Assert.False(forged.VerifyHash(ClientNonce, AsNonce, GrantEndpoint));
        Assert.False(new InteractionFinishCallback { InteractRef = InteractRef }.VerifyHash(ClientNonce, AsNonce, GrantEndpoint));
    }
}
