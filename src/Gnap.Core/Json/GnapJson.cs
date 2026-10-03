using System.Text.Json;
using System.Text.Encodings.Web;
using System.Text.Json.Serialization;
using Gnap.Core.Keys;
using Gnap.Core.Models;

namespace Gnap.Core.Json;

/// <summary>
/// The source-generated serializer context for all GNAP protocol models. All
/// (de)serialization in this library goes through this context; no reflection
/// based serialization is used, keeping the models AOT- and trimming-safe.
/// </summary>
[JsonSourceGenerationOptions(DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(GrantRequest))]
[JsonSerializable(typeof(GrantResponse))]
[JsonSerializable(typeof(ContinueRequest))]
[JsonSerializable(typeof(InteractionFinishCallback))]
[JsonSerializable(typeof(AccessTokenRequest))]
[JsonSerializable(typeof(AccessTokenResponse))]
[JsonSerializable(typeof(AccessRight))]
[JsonSerializable(typeof(ClientInstance))]
[JsonSerializable(typeof(ClientDisplay))]
[JsonSerializable(typeof(GnapKey))]
[JsonSerializable(typeof(ProofMethod))]
[JsonSerializable(typeof(JsonWebKey))]
[JsonSerializable(typeof(RequestUser))]
[JsonSerializable(typeof(SubjectRequest))]
[JsonSerializable(typeof(SubjectResponse))]
[JsonSerializable(typeof(SubjectIdentifier))]
[JsonSerializable(typeof(SubjectAssertion))]
[JsonSerializable(typeof(InteractRequest))]
[JsonSerializable(typeof(InteractFinish))]
[JsonSerializable(typeof(InteractHints))]
[JsonSerializable(typeof(StartMode))]
[JsonSerializable(typeof(InteractResponse))]
[JsonSerializable(typeof(UserCodeUri))]
[JsonSerializable(typeof(ContinueResponse))]
[JsonSerializable(typeof(TokenManagement))]
[JsonSerializable(typeof(GnapError))]
[JsonSerializable(typeof(GnapErrorCode))]
[JsonSerializable(typeof(IList<SubjectIdentifier>))]
[JsonSerializable(typeof(IList<SubjectAssertion>))]
[JsonSerializable(typeof(IList<AccessRight>))]
[JsonSerializable(typeof(IList<AccessTokenRequest>))]
[JsonSerializable(typeof(IList<AccessTokenResponse>))]
[JsonSerializable(typeof(IList<StartMode>))]
[JsonSerializable(typeof(IList<string>))]
[JsonSerializable(typeof(string))]
[JsonSerializable(typeof(Dictionary<string, JsonElement>))]
[JsonSerializable(typeof(Dictionary<string, string>))]
[JsonSerializable(typeof(JsonElement))]
public sealed partial class GnapJsonContext : JsonSerializerContext
{
    /// <summary>
    /// The context used for messages sent on the wire. Unlike <see cref="Default"/>,
    /// it does not apply the HTML-safe escaping of <see cref="JavaScriptEncoder.Default"/>
    /// (<c>+</c>, <c>&amp;</c>, <c>&lt;</c>, non-ASCII, ...): GNAP bodies are
    /// <c>application/json</c>, never embedded in HTML, and some peers (e.g. Rafiki)
    /// recompute <c>Content-Digest</c> over their own re-serialization of the parsed
    /// body, which only matches when the client escapes like <c>JSON.stringify</c>.
    /// </summary>
    public static GnapJsonContext Wire { get; } = new(new JsonSerializerOptions
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    });
}

/// <summary>Convenience entry points for (de)serializing GNAP messages.</summary>
public static class GnapJson
{
    /// <summary>Serializes a grant request.</summary>
    public static string Serialize(GrantRequest request) =>
        JsonSerializer.Serialize(request, GnapJsonContext.Wire.GrantRequest);

    /// <summary>Serializes a grant response.</summary>
    public static string Serialize(GrantResponse response) =>
        JsonSerializer.Serialize(response, GnapJsonContext.Wire.GrantResponse);

    /// <summary>Serializes a continuation request.</summary>
    public static string Serialize(ContinueRequest request) =>
        JsonSerializer.Serialize(request, GnapJsonContext.Wire.ContinueRequest);

    /// <summary>Serializes an interaction finish <c>push</c> body (RFC 9635 Section 4.2.2).</summary>
    public static string Serialize(InteractionFinishCallback callback) =>
        JsonSerializer.Serialize(callback, GnapJsonContext.Wire.InteractionFinishCallback);

    /// <summary>Parses a grant request.</summary>
    /// <exception cref="JsonException">The JSON is malformed.</exception>
    public static GrantRequest? DeserializeGrantRequest(string json) =>
        JsonSerializer.Deserialize(json, GnapJsonContext.Default.GrantRequest);

    /// <summary>Parses a grant response.</summary>
    /// <exception cref="JsonException">The JSON is malformed.</exception>
    public static GrantResponse? DeserializeGrantResponse(string json) =>
        JsonSerializer.Deserialize(json, GnapJsonContext.Default.GrantResponse);

    /// <summary>Parses a continuation request.</summary>
    /// <exception cref="JsonException">The JSON is malformed.</exception>
    public static ContinueRequest? DeserializeContinueRequest(string json) =>
        JsonSerializer.Deserialize(json, GnapJsonContext.Default.ContinueRequest);

    /// <summary>Parses an interaction finish <c>push</c> body (RFC 9635 Section 4.2.2).</summary>
    /// <exception cref="JsonException">The JSON is malformed.</exception>
    public static InteractionFinishCallback? DeserializeFinishCallback(string json) =>
        JsonSerializer.Deserialize(json, GnapJsonContext.Default.InteractionFinishCallback);
}
