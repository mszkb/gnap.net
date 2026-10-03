using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace Gnap.Core.Json;

/// <summary>Shared low-level helpers for the hand-written union converters.</summary>
internal static class JsonHelpers
{
    /// <summary>Resolves source-generated metadata for a nested type in an AOT-safe way.</summary>
    public static JsonTypeInfo<T> TypeInfo<T>(JsonSerializerOptions options) =>
        (JsonTypeInfo<T>)options.GetTypeInfo(typeof(T));

    /// <summary>Reads an array of strings, tolerating a JSON null.</summary>
    public static List<string>? ReadStringList(ref Utf8JsonReader reader)
    {
        if (reader.TokenType == JsonTokenType.Null)
        {
            return null;
        }

        if (reader.TokenType != JsonTokenType.StartArray)
        {
            throw new JsonException("Expected an array of strings.");
        }

        var list = new List<string>();
        while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
        {
            if (reader.TokenType != JsonTokenType.String)
            {
                throw new JsonException("Expected a string array element.");
            }

            list.Add(reader.GetString()!);
        }

        return list;
    }

    /// <summary>Writes a named array of strings.</summary>
    public static void WriteStringArray(Utf8JsonWriter writer, string name, IEnumerable<string> values)
    {
        writer.WriteStartArray(name);
        foreach (var value in values)
        {
            writer.WriteStringValue(value);
        }

        writer.WriteEndArray();
    }

    /// <summary>Writes captured extension members back out verbatim.</summary>
    public static void WriteExtensionData(Utf8JsonWriter writer, IDictionary<string, JsonElement>? fields)
    {
        if (fields is null)
        {
            return;
        }

        foreach (var (name, value) in fields)
        {
            writer.WritePropertyName(name);
            value.WriteTo(writer);
        }
    }

    /// <summary>Adds an unknown member to the (lazily created) extension dictionary.</summary>
    public static void CaptureExtensionMember(
        ref Utf8JsonReader reader,
        ref IDictionary<string, JsonElement>? fields,
        string name)
    {
        fields ??= new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        fields[name] = JsonElement.ParseValue(ref reader);
    }

    /// <summary>Creates a standalone JSON string element without reflection.</summary>
    public static JsonElement StringElement(string value)
    {
        using var document = JsonDocument.Parse(JsonSerializer.Serialize(value, GnapJsonContext.Default.String));
        return document.RootElement.Clone();
    }
}
