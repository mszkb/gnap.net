using Gnap.HttpMessageSignatures;

namespace Gnap.Core.Proofing;

/// <summary>
/// Attaches a key possession proof (RFC 9635 Section 7.3) to an outgoing HTTP
/// request. Implementations exist per proofing method (<c>httpsig</c>, and via
/// extension <c>mtls</c>, <c>jwsd</c>, <c>jws</c>).
/// </summary>
public interface IKeyProofer
{
    /// <summary>The registered proofing method name this proofer implements.</summary>
    string Method { get; }

    /// <summary>Signs the request in place, adding all headers the method requires.</summary>
    Task AddProofAsync(HttpRequestMessage request, CancellationToken cancellationToken = default);
}

/// <summary>
/// Validates the key possession proof on a received HTTP message against the
/// key the sender claims to control.
/// </summary>
public interface IKeyProofValidator
{
    /// <summary>The registered proofing method name this validator implements.</summary>
    string Method { get; }

    /// <summary>Validates the proof on the message against the expected key.</summary>
    Task<KeyProofResult> ValidateAsync(KeyProofContext context, CancellationToken cancellationToken = default);
}

/// <summary>The message and expected key material a proof is validated against.</summary>
public sealed class KeyProofContext
{
    /// <summary>The received message.</summary>
    public required IHttpMessageContext Message { get; init; }

    /// <summary>The expected key of the sender, bound to its signature algorithm.</summary>
    public required SignatureAlgorithm Key { get; init; }

    /// <summary>The raw message content, when the message has content.</summary>
    public ReadOnlyMemory<byte>? Content { get; init; }
}

/// <summary>The outcome of validating a key proof.</summary>
public sealed class KeyProofResult
{
    private KeyProofResult(bool succeeded, string? failureReason)
    {
        Succeeded = succeeded;
        FailureReason = failureReason;
    }

    /// <summary>Whether the proof is valid for the expected key.</summary>
    public bool Succeeded { get; }

    /// <summary>A diagnostic reason when validation failed. Log it; do not echo it to clients.</summary>
    public string? FailureReason { get; }

    /// <summary>A successful validation.</summary>
    public static KeyProofResult Success { get; } = new(true, null);

    /// <summary>A failed validation with a diagnostic reason.</summary>
    public static KeyProofResult Failure(string reason) => new(false, reason);
}
