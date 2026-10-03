using System.Text.Json.Serialization;
using Gnap.Client.Discovery;

namespace Gnap.Client.Json;

/// <summary>Source-generated serializer context for the client-only models (AOT- and trimming-safe).</summary>
[JsonSourceGenerationOptions(DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(AuthorizationServerMetadata))]
internal sealed partial class GnapClientJsonContext : JsonSerializerContext;
