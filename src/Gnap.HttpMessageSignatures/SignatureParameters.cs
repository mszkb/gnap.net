using Gnap.HttpMessageSignatures.StructuredFields;

namespace Gnap.HttpMessageSignatures;

/// <summary>
/// The covered components and signature parameters of one HTTP message signature
/// (RFC 9421 Section 2.3): the value serialized into the <c>Signature-Input</c>
/// field and covered by the <c>@signature-params</c> line of the signature base.
/// </summary>
public sealed class SignatureParameters
{
    private readonly List<SignatureComponent> _components = [];
    private readonly SfParameters _parameters = new();

    /// <summary>The covered components, in signature base order.</summary>
    public IReadOnlyList<SignatureComponent> Components => _components;

    /// <summary>All signature parameters in serialization order, including unknown ones.</summary>
    public IReadOnlyList<KeyValuePair<string, SfValue>> Parameters => _parameters;

    /// <summary>The <c>created</c> timestamp, if present.</summary>
    public DateTimeOffset? Created => GetInteger("created") is { } v ? DateTimeOffset.FromUnixTimeSeconds(v) : null;

    /// <summary>The <c>expires</c> timestamp, if present.</summary>
    public DateTimeOffset? Expires => GetInteger("expires") is { } v ? DateTimeOffset.FromUnixTimeSeconds(v) : null;

    /// <summary>The <c>keyid</c> parameter, if present.</summary>
    public string? KeyId => GetString("keyid");

    /// <summary>The <c>alg</c> parameter, if present.</summary>
    public string? Algorithm => GetString("alg");

    /// <summary>The <c>nonce</c> parameter, if present.</summary>
    public string? Nonce => GetString("nonce");

    /// <summary>The <c>tag</c> parameter, if present.</summary>
    public string? Tag => GetString("tag");

    private long? GetInteger(string name) => _parameters.Get(name) is SfInteger i ? i.Value : null;

    private string? GetString(string name) => _parameters.Get(name) is SfString s ? s.Value : null;

    /// <summary>Appends a covered component.</summary>
    /// <exception cref="HttpMessageSignatureException">The component is already covered.</exception>
    public SignatureParameters AddComponent(SignatureComponent component)
    {
        if (_components.Contains(component))
        {
            throw new HttpMessageSignatureException($"Component {component} is covered more than once.");
        }

        if (component.Name == "@signature-params")
        {
            throw new HttpMessageSignatureException("@signature-params cannot be an explicitly covered component.");
        }

        _components.Add(component);
        return this;
    }

    /// <summary>Appends several covered components.</summary>
    public SignatureParameters AddComponents(IEnumerable<SignatureComponent> components)
    {
        foreach (var component in components)
        {
            AddComponent(component);
        }

        return this;
    }

    /// <summary>Sets the <c>created</c> parameter (seconds precision).</summary>
    public SignatureParameters WithCreated(DateTimeOffset created) =>
        WithParameter("created", new SfInteger(created.ToUnixTimeSeconds()));

    /// <summary>Sets the <c>expires</c> parameter (seconds precision).</summary>
    public SignatureParameters WithExpires(DateTimeOffset expires) =>
        WithParameter("expires", new SfInteger(expires.ToUnixTimeSeconds()));

    /// <summary>Sets the <c>keyid</c> parameter.</summary>
    public SignatureParameters WithKeyId(string keyId) => WithParameter("keyid", new SfString(keyId));

    /// <summary>Sets the <c>alg</c> parameter.</summary>
    public SignatureParameters WithAlgorithm(string algorithm) => WithParameter("alg", new SfString(algorithm));

    /// <summary>Sets the <c>nonce</c> parameter.</summary>
    public SignatureParameters WithNonce(string nonce) => WithParameter("nonce", new SfString(nonce));

    /// <summary>Sets the <c>tag</c> parameter.</summary>
    public SignatureParameters WithTag(string tag) => WithParameter("tag", new SfString(tag));

    /// <summary>Sets an arbitrary signature parameter.</summary>
    public SignatureParameters WithParameter(string name, SfValue value)
    {
        _parameters.Add(name, value);
        return this;
    }

    /// <summary>
    /// Serializes the covered components and parameters as an RFC 8941 inner list —
    /// the exact value of the <c>@signature-params</c> base line and of this
    /// signature's <c>Signature-Input</c> dictionary member.
    /// </summary>
    public string Serialize() => ToSfInnerList().ToString();

    /// <summary>Converts to the structured field inner list form.</summary>
    public SfInnerList ToSfInnerList() =>
        new(_components.Select(c => c.ToSfItem()), new SfParameters(_parameters));

    /// <summary>Parses the inner list member of a <c>Signature-Input</c> dictionary.</summary>
    /// <exception cref="HttpMessageSignatureException">The inner list is not a valid signature parameter set.</exception>
    public static SignatureParameters FromSfInnerList(SfInnerList innerList)
    {
        var result = new SignatureParameters();
        foreach (var item in innerList.Items)
        {
            result.AddComponent(SignatureComponent.FromSfItem(item));
        }

        foreach (var (key, value) in innerList.Parameters)
        {
            result._parameters.Add(key, value);
        }

        return result;
    }
}
