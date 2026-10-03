using System.Buffers.Text;
using System.Net;
using System.Text;
using System.Text.Json;
using Gnap.AspNetCore.AuthorizationServer.Stores;
using Gnap.AspNetCore.AuthorizationServer.Tokens;
using Gnap.AspNetCore.ResourceServer;
using Gnap.AspNetCore.Tests.Infrastructure;
using Gnap.Client;
using Gnap.Core;
using Gnap.Core.Keys;
using Gnap.Core.Models;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Gnap.AspNetCore.Tests;

/// <summary>RFC 9767 RS ↔ AS connection: discovery and resource set registration.</summary>
public class ResourceRegistrationTests
{
    private static readonly Uri Register = new("http://localhost/gnap/resource");
    private const string Body = """{"access":[{"type":"photo-api","actions":["read"]}],"resource_server":"photo-rs"}""";

    [Fact]
    public async Task Discovery_AdvertisesRsFacingEndpoints()
    {
        await using var rs = await RsHarness.StartAsync(TokenValidation.Jwt);

        var metadata = await rs.Services.GetRequiredService<GnapAsRsClient>().GetMetadataAsync();

        Assert.Equal(AsHarness.GrantEndpoint, metadata.GrantRequestEndpoint);
        Assert.Equal(new Uri("http://localhost/gnap/introspect"), metadata.IntrospectionEndpoint);
        Assert.Equal(Register, metadata.ResourceRegistrationEndpoint);
        Assert.Equal(["jwt-signed"], metadata.TokenFormatsSupported);
        Assert.Equal(["httpsig"], metadata.KeyProofsSupported);
    }

    [Fact]
    public async Task OpaqueFormat_AdvertisesNoTokenFormats()
    {
        await using var h = await AsHarness.StartAsync();
        var json = JsonDocument.Parse(await h.Http.GetStringAsync(new Uri("http://localhost/.well-known/gnap-as-rs"))).RootElement;

        Assert.False(json.TryGetProperty("token_formats_supported", out _));
        Assert.Equal(Register.AbsoluteUri, json.GetProperty("resource_registration_endpoint").GetString());
    }

    [Fact]
    public async Task RegisteredRs_ObtainsReference()
    {
        await using var rs = await RsHarness.StartAsync();
        var client = rs.Services.GetRequiredService<GnapAsRsClient>();

        var first = await client.RegisterResourceSetAsync([RsHarness.PhotoRead]);
        var second = await client.RegisterResourceSetAsync([AccessRight.ForReference("other")]);

        Assert.NotEqual(first, second);
        var stored = await rs.As.Services.GetRequiredService<IResourceSetStore>().FindAsync(first);
        Assert.Equal("photo-api", Assert.Single(stored!.Access).Type);
        Assert.Equal(rs.As.Time.GetUtcNow(), stored.RegisteredAt);
    }

    [Fact]
    public async Task Registration_RequiresAuthenticatedRegisteredRs()
    {
        await using var rs = await RsHarness.StartAsync();
        var rsKey = GnapClientKey.FromJwk(rs.RsKey);
        var impostor = GnapClientKey.FromJwk(AsHarness.NewEcKey("rs-key"));

        var unsigned = await rs.As.SendSignedAsync(HttpMethod.Post, Register, null, json: Body);
        var wrongKey = await rs.As.SendSignedAsync(HttpMethod.Post, Register, impostor, json: Body);
        var unknownRs = await rs.As.SendSignedAsync(HttpMethod.Post, Register, rsKey, json: Body.Replace("photo-rs", "other-rs", StringComparison.Ordinal));
        var malformed = await rs.As.SendSignedAsync(HttpMethod.Post, Register, rsKey, json: """{"access":[],"resource_server":"photo-rs"}""");
        var valid = await rs.As.SendSignedAsync(HttpMethod.Post, Register, rsKey, json: Body);

        Assert.All(new[] { unsigned, wrongKey, unknownRs }, r =>
        {
            Assert.Equal(HttpStatusCode.Unauthorized, r.Status);
            Assert.Contains("invalid_client", r.Body, StringComparison.Ordinal);
        });
        Assert.Equal(HttpStatusCode.BadRequest, malformed.Status);
        Assert.Equal(HttpStatusCode.OK, valid.Status);
        Assert.True(JsonDocument.Parse(valid.Body).RootElement.TryGetProperty("resource_reference", out _));
    }

    [Fact]
    public async Task Registration_CanBeDisabled()
    {
        await using var h = await AsHarness.StartAsync(configure: o => o.EnableResourceRegistration = false);

        var (status, _) = await h.SendSignedAsync(HttpMethod.Post, Register, null, json: Body);
        var json = JsonDocument.Parse(await h.Http.GetStringAsync(new Uri("http://localhost/.well-known/gnap-as-rs"))).RootElement;

        Assert.Equal(HttpStatusCode.NotFound, status);
        Assert.False(json.TryGetProperty("resource_registration_endpoint", out _));
    }

    [Fact]
    public async Task ConfiguredAccessReference_IsAnnouncedWithoutRegistration()
    {
        await using var rs = await RsHarness.StartAsync(configure: o =>
        {
            o.AccessReference = "photos";
            o.GrantEndpoint = new Uri("https://as.example/tx");
        });

        using var response = await rs.Http.GetAsync(RsHarness.Photos);

        Assert.Equal("GNAP as_uri=\"https://as.example/tx\", access=\"photos\"", response.Headers.WwwAuthenticate.ToString());
        Assert.Equal(0, rs.Backchannel.Count("/gnap/resource"));
        Assert.Equal(0, rs.Backchannel.Count("/.well-known/gnap-as-rs"));
    }

    [Fact]
    public async Task UnreachableAs_DegradesChallengeAndRetries()
    {
        await using var rs = await RsHarness.StartAsync(configure: o => o.ResourceServerId = "not-registered");

        using var first = await rs.Http.GetAsync(RsHarness.Photos);
        using var second = await rs.Http.GetAsync(RsHarness.Photos);

        // Discovery works, registration is refused: as_uri only, and registration is retried.
        Assert.Equal("GNAP as_uri=\"http://localhost/gnap/tx\"", first.Headers.WwwAuthenticate.ToString());
        Assert.Equal(2, rs.Backchannel.Count("/gnap/resource"));
        Assert.Equal(1, rs.Backchannel.Count("/.well-known/gnap-as-rs"));
    }
}

/// <summary>Local verification of JWT access tokens.</summary>
public class JwtTokenValidatorTests
{
    private static readonly JsonWebKey AsKey = AsHarness.NewEcKey("as-key");
    private static readonly JsonWebKey ClientJwk = AsHarness.NewEcKey("client");
    private const string Issuer = "https://as.example/tx";

    private static async Task<string> IssueAsync(JsonWebKey signingKey, GnapKey? boundKey, string issuer = Issuer) =>
        await new JwtTokenFormat(signingKey).CreateTokenAsync(new AccessTokenDescriptor
        {
            TokenId = "t1",
            GrantId = "g1",
            Issuer = issuer,
            Access = [RsHarness.PhotoRead],
            BoundKey = boundKey,
            IssuedAt = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000),
            ExpiresAt = DateTimeOffset.FromUnixTimeSeconds(1_700_003_600),
            InstanceId = "i1",
            ResourceOwner = "alice",
        });

    private static JwtTokenValidator Validator => new([AsKey.ToPublicKey()], Issuer);

    [Fact]
    public async Task ValidToken_IsDescribed()
    {
        var info = await Validator.ValidateAsync(await IssueAsync(AsKey, GnapKey.ForHttpSig(ClientJwk)));

        Assert.NotNull(info);
        Assert.Equal(ClientJwk.X, info.Key!.Jwk!.X);
        Assert.Equal("httpsig", info.Key.Proof!.Method);
        Assert.False(info.IsBearer);
        Assert.Equal("alice", info.Subject);
        Assert.Equal("i1", info.InstanceId);
        Assert.Equal("t1", info.TokenId);
        Assert.Equal(Issuer, info.Issuer);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1_700_003_600), info.ExpiresAt);
        Assert.Equal("photo-api", Assert.Single(info.Access).Type);
    }

    [Fact]
    public async Task BearerToken_IsFlagged()
    {
        var info = await Validator.ValidateAsync(await IssueAsync(AsKey, null));

        Assert.True(info!.IsBearer);
        Assert.Null(info.Key);
    }

    [Fact]
    public async Task ForgedOrManipulatedTokens_AreRejected()
    {
        var valid = await IssueAsync(AsKey, GnapKey.ForHttpSig(ClientJwk));
        var parts = valid.Split('.');
        var payload = Encoding.UTF8.GetString(Base64Url.DecodeFromChars(parts[1]));

        string WithPayload(string json) => $"{parts[0]}.{Base64Url.EncodeToString(Encoding.UTF8.GetBytes(json))}.{parts[2]}";

        var attacker = AsHarness.NewEcKey("attacker");
        var cases = new[]
        {
            await IssueAsync(AsHarness.NewEcKey("as-key"), GnapKey.ForHttpSig(ClientJwk)), // other signing key, same kid
            await IssueAsync(AsKey, GnapKey.ForHttpSig(ClientJwk), issuer: "https://evil.example/tx"),
            WithPayload(payload.Replace("\"read\"", "\"delete\"", StringComparison.Ordinal)), // escalated rights
            WithPayload(payload.Replace(ClientJwk.X!, attacker.X!, StringComparison.Ordinal)), // rebound key (signature breaks)
            $"{parts[0]}.{parts[1]}", // no signature
            $"{parts[0]}.{parts[1]}.", // empty signature
            "not-a-jwt",
            "a.b.c",
        };

        foreach (var token in cases)
        {
            Assert.Null(await Validator.ValidateAsync(token));
        }
    }

    [Fact]
    public async Task KeyNotMatchingThumbprint_IsRejected()
    {
        // A token whose key claim disagrees with cnf.jkt, signed by the real AS key
        // (e.g. a buggy or tampered issuer): never trusted.
        var valid = await IssueAsync(AsKey, GnapKey.ForHttpSig(ClientJwk));
        var parts = valid.Split('.');
        var payload = Encoding.UTF8.GetString(Base64Url.DecodeFromChars(parts[1]))
            .Replace(ClientJwk.X!, AsHarness.NewEcKey("x").X!, StringComparison.Ordinal);
        var header = parts[0];
        var signingInput = $"{header}.{Base64Url.EncodeToString(Encoding.UTF8.GetBytes(payload))}";
        var signature = AsKey.ToSignatureAlgorithm().Sign(Encoding.ASCII.GetBytes(signingInput));

        Assert.Null(await Validator.ValidateAsync($"{signingInput}.{Base64Url.EncodeToString(signature)}"));
    }

    [Fact]
    public async Task IssuerCheck_IsOptional()
    {
        var token = await IssueAsync(AsKey, null, issuer: "https://other.example/tx");

        Assert.Null(await Validator.ValidateAsync(token));
        Assert.NotNull(await new JwtTokenValidator([AsKey]).ValidateAsync(token));
    }

    [Fact]
    public void RequiresAKey() =>
        Assert.Throws<ArgumentException>(() => new JwtTokenValidator([]));
}

/// <summary>Introspection-response parsing and the access requirement.</summary>
public class GnapTokenInfoAndRequirementTests
{
    [Theory]
    [InlineData("""{"active":false}""")]
    [InlineData("""{"access":[]}""")]
    [InlineData("""{"active":true,"access":"photo"}""")]
    [InlineData("""{"active":true,"key":42}""")]
    [InlineData("""{"active":true,"flags":"bearer"}""")]
    [InlineData("""{"active":true,"flags":[1]}""")]
    [InlineData("""[]""")]
    public void InactiveOrMalformedIntrospection_YieldsNull(string json) =>
        Assert.Null(GnapTokenInfo.Parse(JsonDocument.Parse(json).RootElement, requireActive: true));

    [Fact]
    public void TokenWithoutKeyOrBearerFlag_IsNotBearer()
    {
        var info = GnapTokenInfo.Parse(JsonDocument.Parse("""{"active":true,"access":["photos"]}""").RootElement, requireActive: true)!;

        Assert.False(info.IsBearer);
        Assert.Null(info.Key);
        Assert.Equal("photos", Assert.Single(info.Access).Reference);
    }

    [Fact]
    public void KeyReference_IsKept()
    {
        var info = GnapTokenInfo.Parse(JsonDocument.Parse("""{"active":true,"key":"key-ref","flags":["bearer"]}""").RootElement, requireActive: true)!;

        Assert.True(info.Key!.IsReference);
        Assert.False(info.IsBearer); // a key wins over the flag
    }

    [Fact]
    public void Requirement_MatchesReferencesAndTypedRights()
    {
        var read = new AccessRight { Type = "photo-api", Actions = ["read", "write"], Locations = ["https://rs.example/photos"] };

        Assert.True(new GnapAccessRequirement("photo-api", ["read"]).IsSatisfiedBy(read));
        Assert.True(new GnapAccessRequirement("photo-api", ["read", "write"], ["https://rs.example/photos"]).IsSatisfiedBy(read));
        Assert.True(new GnapAccessRequirement("photo-api").IsSatisfiedBy(read));
        Assert.False(new GnapAccessRequirement("photo-api", ["delete"]).IsSatisfiedBy(read));
        Assert.False(new GnapAccessRequirement("photo-api", [], ["https://other.example"]).IsSatisfiedBy(read));
        Assert.False(new GnapAccessRequirement("other-api").IsSatisfiedBy(read));
        Assert.False(new GnapAccessRequirement("photo-api").IsSatisfiedBy(new AccessRight { Type = "photo-api-v2" }));

        Assert.True(new GnapAccessRequirement("photos").IsSatisfiedBy(AccessRight.ForReference("photos")));
        Assert.False(new GnapAccessRequirement("photo-api").IsSatisfiedBy(AccessRight.ForReference("photos")));
        Assert.True(new GnapAccessRequirement(r => r.Datatypes?.Contains("metadata") is true)
            .IsSatisfiedBy(new AccessRight { Type = "x", Datatypes = ["metadata"] }));
    }
}
