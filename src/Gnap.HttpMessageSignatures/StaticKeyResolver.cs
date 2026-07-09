namespace Gnap.HttpMessageSignatures;

/// <summary>
/// An in-memory <see cref="IVerificationKeyResolver"/> mapping <c>keyid</c> values
/// to algorithm-bound keys. Suitable for tests, demos and small deployments.
/// </summary>
public sealed class StaticKeyResolver : IVerificationKeyResolver
{
    private readonly Dictionary<string, SignatureAlgorithm> _keys = [];

    /// <summary>Registers a key under its <c>keyid</c>.</summary>
    public StaticKeyResolver Add(string keyId, SignatureAlgorithm algorithm)
    {
        _keys[keyId] = algorithm;
        return this;
    }

    /// <inheritdoc />
    public ValueTask<SignatureAlgorithm?> ResolveAsync(string? keyId, string? algorithm, CancellationToken cancellationToken = default)
    {
        var result = keyId is not null && _keys.TryGetValue(keyId, out var found) ? found : null;
        return ValueTask.FromResult(result);
    }
}
