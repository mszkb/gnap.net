using System.Text;
using Gnap.HttpMessageSignatures.StructuredFields;

namespace Gnap.HttpMessageSignatures;

/// <summary>
/// Assembles the canonical signature base of an HTTP message signature
/// (RFC 9421 Section 2.5): one line per covered component followed by the
/// <c>@signature-params</c> line.
/// </summary>
public static class SignatureBaseBuilder
{
    /// <summary>
    /// The structured field types used when re-serializing a field covered with the
    /// <c>sf</c> or <c>key</c> component parameter. Pre-populated with well-known
    /// fields; applications may register additional ones.
    /// </summary>
    public static StructuredFieldRegistry FieldTypes { get; } = new();

    /// <summary>Builds the signature base for the given message and parameters.</summary>
    /// <exception cref="HttpMessageSignatureException">
    /// A covered component is missing from the message or cannot be canonicalized.
    /// </exception>
    public static string Build(IHttpMessageContext message, SignatureParameters parameters)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(parameters);

        var sb = new StringBuilder();
        foreach (var component in parameters.Components)
        {
            foreach (var value in ResolveComponentValues(message, component))
            {
                sb.Append(component.ToSfItem().ToString());
                sb.Append(": ");
                sb.Append(value);
                sb.Append('\n');
            }
        }

        sb.Append("\"@signature-params\": ");
        sb.Append(parameters.Serialize());
        return sb.ToString();
    }

    private static IEnumerable<string> ResolveComponentValues(IHttpMessageContext message, SignatureComponent component)
    {
        var context = message;
        if (component.FromRequest)
        {
            if (message.IsRequest)
            {
                throw new HttpMessageSignatureException($"Component {component} uses the 'req' flag, which is only valid when signing a response.");
            }

            context = message.AssociatedRequest
                ?? throw new HttpMessageSignatureException("The response has no associated request for a 'req' component.");
        }

        return component.IsDerived
            ? ResolveDerivedComponent(context, component)
            : [ResolveFieldComponent(context, component)];
    }

    private static IEnumerable<string> ResolveDerivedComponent(IHttpMessageContext context, SignatureComponent component)
    {
        if (component.Name == "@status")
        {
            if (component.FromRequest || context.IsRequest)
            {
                throw new HttpMessageSignatureException("@status is only defined for response messages.");
            }

            return [context.StatusCode?.ToString(System.Globalization.CultureInfo.InvariantCulture)
                ?? throw new HttpMessageSignatureException("The response has no status code.")];
        }

        if (!context.IsRequest)
        {
            throw new HttpMessageSignatureException($"Derived component {component.Name} on a response requires the 'req' flag.");
        }

        var uri = context.TargetUri
            ?? throw new HttpMessageSignatureException("The request has no target URI.");

        return component.Name switch
        {
            "@method" => [context.Method ?? throw new HttpMessageSignatureException("The request has no method.")],
            "@target-uri" => [uri.AbsoluteUri],
            "@authority" => [GetAuthority(uri)],
            "@scheme" => [uri.Scheme],
            "@request-target" => [uri.PathAndQuery],
            "@path" => [uri.AbsolutePath],
            "@query" => [GetQuery(uri)],
            "@query-param" => ResolveQueryParam(uri, component),
            _ => throw new HttpMessageSignatureException($"Unknown derived component {component.Name}."),
        };
    }

    private static string GetAuthority(Uri uri)
    {
        var host = uri.Host.ToLowerInvariant();
        return uri.IsDefaultPort ? host : $"{host}:{uri.Port}";
    }

    private static string GetQuery(Uri uri)
    {
        // An absent query is represented by the lone '?' (RFC 9421 Section 2.2.7).
        var query = uri.Query;
        return query.Length == 0 ? "?" : query;
    }

    private static IEnumerable<string> ResolveQueryParam(Uri uri, SignatureComponent component)
    {
        if (component.Parameters.Get("name") is not SfString name)
        {
            throw new HttpMessageSignatureException("@query-param requires a 'name' parameter.");
        }

        var rawQuery = uri.Query.StartsWith('?') ? uri.Query[1..] : uri.Query;
        var values = QueryParameterCodec.Parse(rawQuery)
            .Where(p => QueryParameterCodec.Encode(p.Name) == name.Value)
            .Select(p => QueryParameterCodec.Encode(p.Value))
            .ToArray();

        if (values.Length == 0)
        {
            throw new HttpMessageSignatureException($"Query parameter '{name.Value}' is not present in the target URI.");
        }

        return values;
    }

    private static string ResolveFieldComponent(IHttpMessageContext context, SignatureComponent component)
    {
        var values = context.GetFieldValues(component.Name, component.FromTrailers)
            .Select(CanonicalizeFieldValue)
            .ToArray();

        if (values.Length == 0)
        {
            var location = component.FromTrailers ? "trailers" : "headers";
            throw new HttpMessageSignatureException($"Field '{component.Name}' is not present in the message {location}.");
        }

        var useByteSequence = component.Parameters.Get("bs") is SfBoolean { Value: true };
        var useStrictSerialization = component.Parameters.Get("sf") is SfBoolean { Value: true };
        var key = component.Parameters.Get("key") as SfString;

        if (useByteSequence && (useStrictSerialization || key is not null))
        {
            throw new HttpMessageSignatureException("The 'bs' flag cannot be combined with 'sf' or 'key'.");
        }

        if (useByteSequence)
        {
            return string.Join(", ", values.Select(v => new SfBytes(Encoding.UTF8.GetBytes(v)).ToString()));
        }

        var combined = string.Join(", ", values);
        if (!useStrictSerialization && key is null)
        {
            return combined;
        }

        return ReserializeStructuredField(component.Name, combined, key?.Value);
    }

    private static string ReserializeStructuredField(string fieldName, string combinedValue, string? key)
    {
        var fieldType = FieldTypes.Get(fieldName)
            ?? throw new HttpMessageSignatureException(
                $"Field '{fieldName}' is covered with 'sf' or 'key' but its structured field type is not registered in SignatureBaseBuilder.FieldTypes.");

        try
        {
            switch (fieldType)
            {
                case StructuredFieldType.Dictionary:
                    var dictionary = SfParser.ParseDictionary(combinedValue);
                    if (key is null)
                    {
                        return dictionary.ToString();
                    }

                    var member = dictionary.Get(key)
                        ?? throw new HttpMessageSignatureException($"Dictionary field '{fieldName}' has no member '{key}'.");
                    return member.ToString();

                case StructuredFieldType.List when key is null:
                    return SfParser.ParseList(combinedValue).ToString();

                case StructuredFieldType.Item when key is null:
                    return SfParser.ParseItem(combinedValue).ToString();

                default:
                    throw new HttpMessageSignatureException($"The 'key' parameter requires field '{fieldName}' to be a dictionary.");
            }
        }
        catch (SfParseException e)
        {
            throw new HttpMessageSignatureException($"Field '{fieldName}' is not a valid structured field: {e.Message}", e);
        }
    }

    private static string CanonicalizeFieldValue(string value)
    {
        // Strip leading/trailing whitespace and collapse obs-fold line breaks
        // (RFC 9421 Section 2.1).
        var trimmed = value.Trim(' ', '\t');
        if (!trimmed.Contains('\n') && !trimmed.Contains('\r'))
        {
            return trimmed;
        }

        var parts = trimmed
            .Split(["\r\n", "\n", "\r"], StringSplitOptions.None)
            .Select(p => p.Trim(' ', '\t'));
        return string.Join(" ", parts);
    }
}

/// <summary>The top-level structured field type of an HTTP field, per the field's definition.</summary>
public enum StructuredFieldType
{
    /// <summary>An RFC 8941 item.</summary>
    Item,

    /// <summary>An RFC 8941 list.</summary>
    List,

    /// <summary>An RFC 8941 dictionary.</summary>
    Dictionary,
}

/// <summary>Maps field names to their structured field types for <c>sf</c>/<c>key</c> re-serialization.</summary>
public sealed class StructuredFieldRegistry
{
    private readonly Dictionary<string, StructuredFieldType> _types = new(StringComparer.OrdinalIgnoreCase)
    {
        ["signature"] = StructuredFieldType.Dictionary,
        ["signature-input"] = StructuredFieldType.Dictionary,
        ["content-digest"] = StructuredFieldType.Dictionary,
        ["repr-digest"] = StructuredFieldType.Dictionary,
        ["want-content-digest"] = StructuredFieldType.Dictionary,
        ["want-repr-digest"] = StructuredFieldType.Dictionary,
        ["accept-signature"] = StructuredFieldType.Dictionary,
        ["cache-control"] = StructuredFieldType.Dictionary,
        ["priority"] = StructuredFieldType.Dictionary,
    };

    /// <summary>Registers or overrides the structured field type of a field.</summary>
    public void Register(string fieldName, StructuredFieldType type) => _types[fieldName] = type;

    /// <summary>Returns the registered type, or <see langword="null"/> if unknown.</summary>
    public StructuredFieldType? Get(string fieldName) =>
        _types.TryGetValue(fieldName, out var type) ? type : null;
}
