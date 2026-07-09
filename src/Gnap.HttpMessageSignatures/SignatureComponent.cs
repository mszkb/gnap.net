using Gnap.HttpMessageSignatures.StructuredFields;

namespace Gnap.HttpMessageSignatures;

/// <summary>
/// A message component covered by an HTTP message signature (RFC 9421 Section 2):
/// either an HTTP field name or a derived component such as <c>@method</c>,
/// together with its component parameters (<c>sf</c>, <c>key</c>, <c>bs</c>,
/// <c>tr</c>, <c>req</c>, <c>name</c>).
/// </summary>
public sealed class SignatureComponent : IEquatable<SignatureComponent>
{
    private SignatureComponent(string name, SfParameters parameters)
    {
        Name = name;
        Parameters = parameters;
    }

    /// <summary>The lowercase component name, e.g. <c>content-type</c> or <c>@method</c>.</summary>
    public string Name { get; }

    /// <summary>The component parameters in serialization order.</summary>
    public SfParameters Parameters { get; }

    /// <summary>Whether this is a derived component (name starts with <c>@</c>).</summary>
    public bool IsDerived => Name.StartsWith('@');

    /// <summary>Whether the <c>req</c> flag is set (component taken from the associated request).</summary>
    public bool FromRequest => Parameters.Get("req") is SfBoolean { Value: true };

    /// <summary>Whether the <c>tr</c> flag is set (field taken from the trailers).</summary>
    public bool FromTrailers => Parameters.Get("tr") is SfBoolean { Value: true };

    /// <summary>The <c>@method</c> derived component.</summary>
    public static SignatureComponent Method { get; } = Derived("@method");

    /// <summary>The <c>@target-uri</c> derived component.</summary>
    public static SignatureComponent TargetUri { get; } = Derived("@target-uri");

    /// <summary>The <c>@authority</c> derived component.</summary>
    public static SignatureComponent Authority { get; } = Derived("@authority");

    /// <summary>The <c>@scheme</c> derived component.</summary>
    public static SignatureComponent Scheme { get; } = Derived("@scheme");

    /// <summary>The <c>@request-target</c> derived component.</summary>
    public static SignatureComponent RequestTarget { get; } = Derived("@request-target");

    /// <summary>The <c>@path</c> derived component.</summary>
    public static SignatureComponent Path { get; } = Derived("@path");

    /// <summary>The <c>@query</c> derived component.</summary>
    public static SignatureComponent Query { get; } = Derived("@query");

    /// <summary>The <c>@status</c> derived component (responses only).</summary>
    public static SignatureComponent Status { get; } = Derived("@status");

    /// <summary>The <c>content-digest</c> field component.</summary>
    public static SignatureComponent ContentDigest { get; } = Field("content-digest");

    /// <summary>Creates a component for an HTTP field. The name is lowercased.</summary>
    public static SignatureComponent Field(string fieldName)
    {
        ArgumentException.ThrowIfNullOrEmpty(fieldName);
        if (fieldName.StartsWith('@'))
        {
            throw new ArgumentException("Field components must not start with '@'; use Derived() for derived components.", nameof(fieldName));
        }

        return new SignatureComponent(fieldName.ToLowerInvariant(), new SfParameters());
    }

    /// <summary>Creates a component for a known derived component name such as <c>@method</c>.</summary>
    public static SignatureComponent Derived(string name)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        if (!name.StartsWith('@'))
        {
            throw new ArgumentException("Derived component names start with '@'.", nameof(name));
        }

        return new SignatureComponent(name.ToLowerInvariant(), new SfParameters());
    }

    /// <summary>Creates a <c>@query-param</c> component for the query parameter with the given (unencoded) name.</summary>
    public static SignatureComponent QueryParam(string parameterName)
    {
        ArgumentException.ThrowIfNullOrEmpty(parameterName);
        var parameters = new SfParameters
        {
            { "name", new SfString(QueryParameterCodec.Encode(parameterName)) },
        };
        return new SignatureComponent("@query-param", parameters);
    }

    /// <summary>Returns a copy with the <c>req</c> flag set, referring to the associated request of a response.</summary>
    public SignatureComponent WithRequest() => WithFlag("req");

    /// <summary>Returns a copy with the <c>tr</c> flag set, taking the field value from the trailers.</summary>
    public SignatureComponent WithTrailers() => WithFlag("tr");

    /// <summary>Returns a copy with the <c>sf</c> flag set, forcing strict structured field re-serialization.</summary>
    public SignatureComponent WithStructuredFieldSerialization() => WithFlag("sf");

    /// <summary>Returns a copy with the <c>bs</c> flag set, wrapping field values as byte sequences.</summary>
    public SignatureComponent WithByteSequenceEncoding() => WithFlag("bs");

    /// <summary>Returns a copy with the <c>key</c> parameter set, selecting a single dictionary member.</summary>
    public SignatureComponent WithKey(string key)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);
        return WithParameter("key", new SfString(key));
    }

    private SignatureComponent WithFlag(string flag) => WithParameter(flag, SfBoolean.True);

    private SignatureComponent WithParameter(string name, SfValue value)
    {
        var parameters = new SfParameters(Parameters) { { name, value } };
        return new SignatureComponent(Name, parameters);
    }

    /// <summary>Reconstructs a component from its parsed structured field item form.</summary>
    /// <exception cref="HttpMessageSignatureException">The item is not a valid component identifier.</exception>
    public static SignatureComponent FromSfItem(SfItem item)
    {
        if (item.Value is not SfString name)
        {
            throw new HttpMessageSignatureException("Component identifiers must be structured field strings.");
        }

        if (name.Value.Length == 0 || name.Value != name.Value.ToLowerInvariant())
        {
            throw new HttpMessageSignatureException($"Component name '{name.Value}' must be non-empty and lowercase.");
        }

        return new SignatureComponent(name.Value, item.Parameters);
    }

    /// <summary>Converts this component into its structured field item form.</summary>
    public SfItem ToSfItem() => new(new SfString(Name), Parameters);

    /// <summary>Returns the serialized component identifier, e.g. <c>"@query-param";name="Pet"</c>.</summary>
    public override string ToString() => ToSfItem().ToString();

    /// <inheritdoc />
    public bool Equals(SignatureComponent? other) => other is not null && ToString() == other.ToString();

    /// <inheritdoc />
    public override bool Equals(object? obj) => Equals(obj as SignatureComponent);

    /// <inheritdoc />
    public override int GetHashCode() => ToString().GetHashCode(StringComparison.Ordinal);
}
