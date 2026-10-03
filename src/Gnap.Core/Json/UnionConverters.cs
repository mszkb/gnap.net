using System.Text.Json;
using System.Text.Json.Serialization;
using Gnap.Core.Keys;
using Gnap.Core.Models;

namespace Gnap.Core.Json;

/// <summary>
/// Serializes a list of <typeparamref name="T"/> as a single JSON object when it
/// has exactly one element and as an array otherwise, matching the
/// object-or-array polymorphism of the <c>access_token</c> field (RFC 9635
/// Sections 2.1 and 3.2).
/// </summary>
internal sealed class OneOrManyConverter<T> : JsonConverter<IList<T>>
    where T : class
{
    public override IList<T> Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var typeInfo = JsonHelpers.TypeInfo<T>(options);
        if (reader.TokenType != JsonTokenType.StartArray)
        {
            return [JsonSerializer.Deserialize(ref reader, typeInfo) ?? throw new JsonException("Unexpected null element.")];
        }

        var list = new List<T>();
        while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
        {
            list.Add(JsonSerializer.Deserialize(ref reader, typeInfo) ?? throw new JsonException("Unexpected null array element."));
        }

        return list;
    }

    public override void Write(Utf8JsonWriter writer, IList<T> value, JsonSerializerOptions options)
    {
        var typeInfo = JsonHelpers.TypeInfo<T>(options);
        if (value.Count == 1)
        {
            JsonSerializer.Serialize(writer, value[0], typeInfo);
            return;
        }

        writer.WriteStartArray();
        foreach (var item in value)
        {
            JsonSerializer.Serialize(writer, item, typeInfo);
        }

        writer.WriteEndArray();
    }
}

/// <summary>Reads and writes the string-or-object form of <see cref="AccessRight"/>.</summary>
internal sealed class AccessRightConverter : JsonConverter<AccessRight>
{
    public override AccessRight Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.String)
        {
            return AccessRight.ForReference(reader.GetString()!);
        }

        if (reader.TokenType != JsonTokenType.StartObject)
        {
            throw new JsonException("An access right must be a string or an object.");
        }

        var result = new AccessRight();
        IDictionary<string, JsonElement>? extra = null;
        while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            var name = reader.GetString()!;
            reader.Read();
            switch (name)
            {
                case "type":
                    result.Type = reader.GetString();
                    break;
                case "actions":
                    result.Actions = JsonHelpers.ReadStringList(ref reader);
                    break;
                case "locations":
                    result.Locations = JsonHelpers.ReadStringList(ref reader);
                    break;
                case "datatypes":
                    result.Datatypes = JsonHelpers.ReadStringList(ref reader);
                    break;
                case "identifier":
                    result.Identifier = reader.GetString();
                    break;
                case "privileges":
                    result.Privileges = JsonHelpers.ReadStringList(ref reader);
                    break;
                default:
                    JsonHelpers.CaptureExtensionMember(ref reader, ref extra, name);
                    break;
            }
        }

        result.AdditionalFields = extra;
        return result;
    }

    public override void Write(Utf8JsonWriter writer, AccessRight value, JsonSerializerOptions options)
    {
        if (value.IsReference)
        {
            writer.WriteStringValue(value.Reference);
            return;
        }

        writer.WriteStartObject();
        if (value.Type is not null)
        {
            writer.WriteString("type", value.Type);
        }

        if (value.Actions is not null)
        {
            JsonHelpers.WriteStringArray(writer, "actions", value.Actions);
        }

        if (value.Locations is not null)
        {
            JsonHelpers.WriteStringArray(writer, "locations", value.Locations);
        }

        if (value.Datatypes is not null)
        {
            JsonHelpers.WriteStringArray(writer, "datatypes", value.Datatypes);
        }

        if (value.Identifier is not null)
        {
            writer.WriteString("identifier", value.Identifier);
        }

        if (value.Privileges is not null)
        {
            JsonHelpers.WriteStringArray(writer, "privileges", value.Privileges);
        }

        JsonHelpers.WriteExtensionData(writer, value.AdditionalFields);
        writer.WriteEndObject();
    }
}

/// <summary>Reads and writes the string-or-object form of <see cref="ProofMethod"/>.</summary>
internal sealed class ProofMethodConverter : JsonConverter<ProofMethod>
{
    public override ProofMethod Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.String)
        {
            return new ProofMethod(reader.GetString()!);
        }

        if (reader.TokenType != JsonTokenType.StartObject)
        {
            throw new JsonException("A proof method must be a string or an object.");
        }

        string? method = null;
        IDictionary<string, JsonElement>? parameters = null;
        while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            var name = reader.GetString()!;
            reader.Read();
            if (name == "method")
            {
                method = reader.GetString();
            }
            else
            {
                JsonHelpers.CaptureExtensionMember(ref reader, ref parameters, name);
            }
        }

        if (string.IsNullOrEmpty(method))
        {
            throw new JsonException("A proof method object requires a 'method' member.");
        }

        return new ProofMethod(method) { Parameters = parameters };
    }

    public override void Write(Utf8JsonWriter writer, ProofMethod value, JsonSerializerOptions options)
    {
        if (value.Parameters is null || value.Parameters.Count == 0)
        {
            writer.WriteStringValue(value.Method);
            return;
        }

        writer.WriteStartObject();
        writer.WriteString("method", value.Method);
        JsonHelpers.WriteExtensionData(writer, value.Parameters);
        writer.WriteEndObject();
    }
}

/// <summary>Reads and writes the string-or-object form of <see cref="GnapKey"/>.</summary>
internal sealed class GnapKeyConverter : JsonConverter<GnapKey>
{
    public override GnapKey Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.String)
        {
            return GnapKey.ForReference(reader.GetString()!);
        }

        if (reader.TokenType != JsonTokenType.StartObject)
        {
            throw new JsonException("A key must be a string or an object.");
        }

        var result = new GnapKey();
        while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            var name = reader.GetString()!;
            reader.Read();
            switch (name)
            {
                case "proof":
                    result.Proof = JsonSerializer.Deserialize(ref reader, JsonHelpers.TypeInfo<ProofMethod>(options));
                    break;
                case "jwk":
                    result.Jwk = JsonSerializer.Deserialize(ref reader, JsonHelpers.TypeInfo<JsonWebKey>(options));
                    break;
                case "cert":
                    result.Cert = reader.GetString();
                    break;
                case "cert#S256":
                    result.CertS256 = reader.GetString();
                    break;
                default:
                    reader.Skip();
                    break;
            }
        }

        return result;
    }

    public override void Write(Utf8JsonWriter writer, GnapKey value, JsonSerializerOptions options)
    {
        if (value.IsReference)
        {
            writer.WriteStringValue(value.Reference);
            return;
        }

        writer.WriteStartObject();
        if (value.Proof is not null)
        {
            writer.WritePropertyName("proof");
            JsonSerializer.Serialize(writer, value.Proof, JsonHelpers.TypeInfo<ProofMethod>(options));
        }

        if (value.Jwk is not null)
        {
            writer.WritePropertyName("jwk");
            JsonSerializer.Serialize(writer, value.Jwk, JsonHelpers.TypeInfo<JsonWebKey>(options));
        }

        if (value.Cert is not null)
        {
            writer.WriteString("cert", value.Cert);
        }

        if (value.CertS256 is not null)
        {
            writer.WriteString("cert#S256", value.CertS256);
        }

        writer.WriteEndObject();
    }
}

/// <summary>Reads and writes the string-or-object form of <see cref="ClientInstance"/>.</summary>
internal sealed class ClientInstanceConverter : JsonConverter<ClientInstance>
{
    public override ClientInstance Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.String)
        {
            return ClientInstance.ForReference(reader.GetString()!);
        }

        if (reader.TokenType != JsonTokenType.StartObject)
        {
            throw new JsonException("A client must be a string or an object.");
        }

        var result = new ClientInstance();
        IDictionary<string, JsonElement>? extra = null;
        while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            var name = reader.GetString()!;
            reader.Read();
            switch (name)
            {
                case "key":
                    result.Key = JsonSerializer.Deserialize(ref reader, JsonHelpers.TypeInfo<GnapKey>(options));
                    break;
                case "class_id":
                    result.ClassId = reader.GetString();
                    break;
                case "display":
                    result.Display = JsonSerializer.Deserialize(ref reader, JsonHelpers.TypeInfo<ClientDisplay>(options));
                    break;
                default:
                    JsonHelpers.CaptureExtensionMember(ref reader, ref extra, name);
                    break;
            }
        }

        result.AdditionalFields = extra;
        return result;
    }

    public override void Write(Utf8JsonWriter writer, ClientInstance value, JsonSerializerOptions options)
    {
        if (value.IsReference)
        {
            writer.WriteStringValue(value.Reference);
            return;
        }

        writer.WriteStartObject();
        if (value.Key is not null)
        {
            writer.WritePropertyName("key");
            JsonSerializer.Serialize(writer, value.Key, JsonHelpers.TypeInfo<GnapKey>(options));
        }

        if (value.ClassId is not null)
        {
            writer.WriteString("class_id", value.ClassId);
        }

        if (value.Display is not null)
        {
            writer.WritePropertyName("display");
            JsonSerializer.Serialize(writer, value.Display, JsonHelpers.TypeInfo<ClientDisplay>(options));
        }

        JsonHelpers.WriteExtensionData(writer, value.AdditionalFields);
        writer.WriteEndObject();
    }
}

/// <summary>Reads and writes the string-or-object form of <see cref="RequestUser"/>.</summary>
internal sealed class RequestUserConverter : JsonConverter<RequestUser>
{
    public override RequestUser Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.String)
        {
            return RequestUser.ForReference(reader.GetString()!);
        }

        if (reader.TokenType != JsonTokenType.StartObject)
        {
            throw new JsonException("A user must be a string or an object.");
        }

        var result = new RequestUser();
        while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            var name = reader.GetString()!;
            reader.Read();
            switch (name)
            {
                case "sub_ids":
                    result.SubIds = JsonSerializer.Deserialize(ref reader, JsonHelpers.TypeInfo<IList<SubjectIdentifier>>(options));
                    break;
                case "assertions":
                    result.Assertions = JsonSerializer.Deserialize(ref reader, JsonHelpers.TypeInfo<IList<SubjectAssertion>>(options));
                    break;
                default:
                    reader.Skip();
                    break;
            }
        }

        return result;
    }

    public override void Write(Utf8JsonWriter writer, RequestUser value, JsonSerializerOptions options)
    {
        if (value.IsReference)
        {
            writer.WriteStringValue(value.Reference);
            return;
        }

        writer.WriteStartObject();
        if (value.SubIds is not null)
        {
            writer.WritePropertyName("sub_ids");
            JsonSerializer.Serialize(writer, value.SubIds, JsonHelpers.TypeInfo<IList<SubjectIdentifier>>(options));
        }

        if (value.Assertions is not null)
        {
            writer.WritePropertyName("assertions");
            JsonSerializer.Serialize(writer, value.Assertions, JsonHelpers.TypeInfo<IList<SubjectAssertion>>(options));
        }

        writer.WriteEndObject();
    }
}

/// <summary>Reads and writes the string-or-object form of <see cref="StartMode"/>.</summary>
internal sealed class StartModeConverter : JsonConverter<StartMode>
{
    public override StartMode Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.String)
        {
            return new StartMode(reader.GetString()!);
        }

        if (reader.TokenType != JsonTokenType.StartObject)
        {
            throw new JsonException("A start mode must be a string or an object.");
        }

        string? mode = null;
        IDictionary<string, JsonElement>? parameters = null;
        while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            var name = reader.GetString()!;
            reader.Read();
            if (name == "mode")
            {
                mode = reader.GetString();
            }
            else
            {
                JsonHelpers.CaptureExtensionMember(ref reader, ref parameters, name);
            }
        }

        if (string.IsNullOrEmpty(mode))
        {
            throw new JsonException("A start mode object requires a 'mode' member.");
        }

        return new StartMode(mode) { Parameters = parameters };
    }

    public override void Write(Utf8JsonWriter writer, StartMode value, JsonSerializerOptions options)
    {
        if (value.Parameters is null || value.Parameters.Count == 0)
        {
            writer.WriteStringValue(value.Mode);
            return;
        }

        writer.WriteStartObject();
        writer.WriteString("mode", value.Mode);
        JsonHelpers.WriteExtensionData(writer, value.Parameters);
        writer.WriteEndObject();
    }
}

/// <summary>Reads and writes the string-or-object form of <see cref="GnapError"/>.</summary>
internal sealed class GnapErrorConverter : JsonConverter<GnapError>
{
    public override GnapError Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.String)
        {
            return new GnapError(new GnapErrorCode(reader.GetString()!));
        }

        if (reader.TokenType != JsonTokenType.StartObject)
        {
            throw new JsonException("An error must be a string or an object.");
        }

        string? code = null;
        string? description = null;
        while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            var name = reader.GetString()!;
            reader.Read();
            switch (name)
            {
                case "code":
                    code = reader.GetString();
                    break;
                case "description":
                    description = reader.GetString();
                    break;
                default:
                    reader.Skip();
                    break;
            }
        }

        if (string.IsNullOrEmpty(code))
        {
            throw new JsonException("An error object requires a 'code' member.");
        }

        return new GnapError(new GnapErrorCode(code), description);
    }

    public override void Write(Utf8JsonWriter writer, GnapError value, JsonSerializerOptions options)
    {
        if (value.Description is null)
        {
            writer.WriteStringValue(value.Code.Value);
            return;
        }

        writer.WriteStartObject();
        writer.WriteString("code", value.Code.Value);
        writer.WriteString("description", value.Description);
        writer.WriteEndObject();
    }
}

/// <summary>Reads and writes <see cref="GnapErrorCode"/> as its string value.</summary>
internal sealed class GnapErrorCodeConverter : JsonConverter<GnapErrorCode>
{
    public override GnapErrorCode Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
        new(reader.GetString() ?? throw new JsonException("An error code must be a string."));

    public override void Write(Utf8JsonWriter writer, GnapErrorCode value, JsonSerializerOptions options) =>
        writer.WriteStringValue(value.Value);
}

/// <summary>
/// Reads and writes <see cref="TokenManagement"/>: the RFC 9635 object form, and the
/// URI-only string form of earlier drafts (still used by Open Payments / Rafiki).
/// </summary>
internal sealed class TokenManagementConverter : JsonConverter<TokenManagement>
{
    public override TokenManagement Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.String)
        {
            return new TokenManagement { Uri = reader.GetString(), IsUriOnly = true };
        }

        if (reader.TokenType != JsonTokenType.StartObject)
        {
            throw new JsonException("'manage' must be an object or a URI string.");
        }

        var result = new TokenManagement();
        while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            var name = reader.GetString()!;
            reader.Read();
            switch (name)
            {
                case "uri":
                    result.Uri = reader.TokenType == JsonTokenType.String
                        ? reader.GetString()
                        : throw new JsonException("'manage.uri' must be a string.");
                    break;
                case "access_token":
                    result.AccessToken = JsonSerializer.Deserialize(ref reader, JsonHelpers.TypeInfo<AccessTokenResponse>(options));
                    break;
                default:
                    reader.Skip();
                    break;
            }
        }

        return result;
    }

    public override void Write(Utf8JsonWriter writer, TokenManagement value, JsonSerializerOptions options)
    {
        if (value.IsUriOnly)
        {
            writer.WriteStringValue(value.Uri);
            return;
        }

        writer.WriteStartObject();
        if (value.Uri is not null)
        {
            writer.WriteString("uri", value.Uri);
        }

        if (value.AccessToken is not null)
        {
            writer.WritePropertyName("access_token");
            JsonSerializer.Serialize(writer, value.AccessToken, JsonHelpers.TypeInfo<AccessTokenResponse>(options));
        }

        writer.WriteEndObject();
    }
}
