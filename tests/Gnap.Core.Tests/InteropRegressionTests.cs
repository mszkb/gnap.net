using System.Buffers.Text;
using Gnap.Core.Json;
using Gnap.Core.Models;
using Xunit;

namespace Gnap.Core.Tests;

/// <summary>
/// Regression tests for the interoperability issues found against Rafiki
/// (Phase 5, docs/interop.md).
/// </summary>
public class InteropRegressionTests
{
    // Rafiki / Open Payments sends `manage` as a bare URI (pre-RFC draft form).
    private const string OpenPaymentsGrantResponse = """
        {"access_token":{"value":"OS9M2PMHKUR64TB8N6BW7OZB8CDFONP219RP1LT0","manage":"https://auth.example/token/dd17a202","expires_in":600,"access":[{"type":"incoming-payment","actions":["create","read"],"identifier":"https://ilp.example/bob"}]},"continue":{"access_token":{"value":"33OMUKMKSKU80UPRY5NM"},"uri":"https://auth.example/continue/4CF492MLVMSW9MKMXKHQ"}}
        """;

    [Fact]
    public void UriOnlyManage_Parses_AndTheAccessTokenAuthorizesItsOwnManagement()
    {
        var response = GnapJson.DeserializeGrantResponse(OpenPaymentsGrantResponse)!;
        var token = Assert.Single(response.AccessToken!);
        var manage = Assert.IsType<TokenManagement>(token.Manage);

        Assert.True(manage.IsUriOnly);
        Assert.Equal("https://auth.example/token/dd17a202", manage.Uri);
        Assert.Null(manage.AccessToken);
        Assert.Equal(token.Value, manage.GetManagementTokenValue(token.Value));
    }

    [Fact]
    public void UriOnlyManage_RoundTripsAsString()
    {
        var response = GnapJson.DeserializeGrantResponse(OpenPaymentsGrantResponse)!;
        Assert.Contains("\"manage\":\"https://auth.example/token/dd17a202\"", GnapJson.Serialize(response), StringComparison.Ordinal);
    }

    [Fact]
    public void ObjectManage_KeepsItsOwnManagementToken()
    {
        var response = GnapJson.DeserializeGrantResponse("""
            {"access_token":{"value":"AT","manage":{"uri":"https://as.example/token/1","access_token":{"value":"MGMT"}},"access":["read"]}}
            """)!;
        var manage = Assert.Single(response.AccessToken!).Manage!;

        Assert.False(manage.IsUriOnly);
        Assert.Equal("MGMT", manage.GetManagementTokenValue("AT"));
        Assert.Contains("\"manage\":{\"uri\":\"https://as.example/token/1\",\"access_token\":{\"value\":\"MGMT\"}}", GnapJson.Serialize(response), StringComparison.Ordinal);
    }

    [Fact]
    public void ObjectManage_WithoutManagementToken_OffersNoManagementToken() =>
        Assert.Null(new TokenManagement { Uri = "https://as.example/token/1" }.GetManagementTokenValue("AT"));

    [Theory]
    [InlineData("42")]
    [InlineData("[]")]
    public void Manage_OfAnotherJsonType_IsRejected(string manage) =>
        Assert.ThrowsAny<System.Text.Json.JsonException>(() =>
            GnapJson.DeserializeGrantResponse($$$"""{"access_token":{"value":"AT","manage":{{{manage}}},"access":["read"]}}"""));

    [Fact]
    public void WireSerialization_DoesNotHtmlEscape()
    {
        // Rafiki recomputes Content-Digest over JSON.stringify(parsed body); the HTML-safe
        // default encoder (+, &, <, ü) broke the digest.
        var json = GnapJson.Serialize(new GrantRequest
        {
            Interact = new InteractRequest
            {
                Start = [new StartMode(StartModes.Redirect)],
                Finish = new InteractFinish { Method = "redirect", Uri = "https://client.example/cb?a=b+c&d=<e>", Nonce = "n" },
            },
            Client = new ClientInstance { Display = new ClientDisplay { Name = "Café's client" } },
        });

        Assert.Contains("https://client.example/cb?a=b+c&d=<e>", json, StringComparison.Ordinal);
        Assert.Contains("Café's client", json, StringComparison.Ordinal);
        Assert.DoesNotContain("\\u", json, StringComparison.Ordinal);
    }

    [Fact]
    public void WireSerialization_StillEscapesJsonSyntax()
    {
        var json = GnapJson.Serialize(new ContinueRequest { InteractRef = "a\"b\\c\n" });
        Assert.Equal("""{"interact_ref":"a\"b\\c\n"}""", json);
    }

    [Fact]
    public void FinishHash_AcceptsCanonicalPaddedBase64_AsSentByRafiki()
    {
        var base64Url = InteractionFinishHash.Compute("VJLO6A4CATR0KRO", "MBDOFXG4Y5CVJCX821LH", "4IFWWIKYB2PQ6U56NL1", "https://server.example.com/tx");
        var standard = Convert.ToBase64String(Base64Url.DecodeFromChars(base64Url));
        Assert.NotEqual(base64Url, standard);

        Assert.True(InteractionFinishHash.Verify(standard, "VJLO6A4CATR0KRO", "MBDOFXG4Y5CVJCX821LH", "4IFWWIKYB2PQ6U56NL1", "https://server.example.com/tx"));
    }

    [Fact]
    public void FinishHash_RejectsOtherSpellings_AndOtherHashes()
    {
        var base64Url = InteractionFinishHash.Compute("VJLO6A4CATR0KRO", "MBDOFXG4Y5CVJCX821LH", "4IFWWIKYB2PQ6U56NL1", "https://server.example.com/tx");
        var standard = Convert.ToBase64String(Base64Url.DecodeFromChars(base64Url));

        Assert.False(InteractionFinishHash.Verify(standard.TrimEnd('='), "VJLO6A4CATR0KRO", "MBDOFXG4Y5CVJCX821LH", "4IFWWIKYB2PQ6U56NL1", "https://server.example.com/tx"));
        Assert.False(InteractionFinishHash.Verify(base64Url + "=", "VJLO6A4CATR0KRO", "MBDOFXG4Y5CVJCX821LH", "4IFWWIKYB2PQ6U56NL1", "https://server.example.com/tx"));
        Assert.False(InteractionFinishHash.Verify(standard, "VJLO6A4CATR0KRO", "MBDOFXG4Y5CVJCX821LH", "OTHER-REF", "https://server.example.com/tx"));
    }
}
