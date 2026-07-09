using System.Text;
using Gnap.HttpMessageSignatures.StructuredFields;

namespace Gnap.HttpMessageSignatures;

/// <summary>Resolves the verification key (bound to its algorithm) for an incoming signature.</summary>
public interface IVerificationKeyResolver
{
    /// <summary>
    /// Returns the algorithm-with-key to verify a signature, or <see langword="null"/>
    /// if the key is unknown. <paramref name="keyId"/> and <paramref name="algorithm"/>
    /// are the signature's <c>keyid</c> and <c>alg</c> parameters (either may be absent).
    /// </summary>
    ValueTask<SignatureAlgorithm?> ResolveAsync(string? keyId, string? algorithm, CancellationToken cancellationToken = default);
}

/// <summary>Settings controlling <see cref="HttpMessageVerifier"/>.</summary>
public sealed class VerificationOptions
{
    /// <summary>The resolver mapping <c>keyid</c>/<c>alg</c> to key material. Required.</summary>
    public required IVerificationKeyResolver KeyResolver { get; init; }

    /// <summary>Tolerated clock difference for <c>created</c>/<c>expires</c> checks. Defaults to 5 minutes.</summary>
    public TimeSpan ClockSkew { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>If set, signatures whose <c>created</c> is older than this are rejected.</summary>
    public TimeSpan? MaxAge { get; init; }

    /// <summary>Whether a <c>created</c> parameter is required. Defaults to <see langword="true"/>.</summary>
    public bool RequireCreated { get; init; } = true;

    /// <summary>Components every accepted signature must cover. Defaults to none.</summary>
    public IReadOnlyCollection<SignatureComponent> RequiredComponents { get; init; } = [];

    /// <summary>The clock used for timestamp checks; overridable for tests.</summary>
    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;
}

/// <summary>The verification outcome for a single signature label.</summary>
/// <param name="Label">The signature label.</param>
/// <param name="Succeeded">Whether this signature verified successfully.</param>
/// <param name="FailureReason">A diagnostic reason when verification failed. Log it; do not echo it to clients.</param>
/// <param name="Parameters">The parsed signature parameters, when available.</param>
public sealed record SignatureVerification(string Label, bool Succeeded, string? FailureReason, SignatureParameters? Parameters);

/// <summary>The overall outcome of verifying a message.</summary>
public sealed class VerificationResult
{
    private VerificationResult(bool succeeded, string? failureReason, IReadOnlyList<SignatureVerification> signatures)
    {
        Succeeded = succeeded;
        FailureReason = failureReason;
        Signatures = signatures;
    }

    /// <summary>Whether every selected signature verified and at least one signature was present.</summary>
    public bool Succeeded { get; }

    /// <summary>A diagnostic reason when <see cref="Succeeded"/> is <see langword="false"/>. Log it; do not echo it to clients.</summary>
    public string? FailureReason { get; }

    /// <summary>The per-signature outcomes.</summary>
    public IReadOnlyList<SignatureVerification> Signatures { get; }

    internal static VerificationResult Failure(string reason) => new(false, reason, []);

    internal static VerificationResult FromSignatures(IReadOnlyList<SignatureVerification> signatures)
    {
        var firstFailure = signatures.FirstOrDefault(s => !s.Succeeded);
        return firstFailure is null
            ? new VerificationResult(true, null, signatures)
            : new VerificationResult(false, $"Signature '{firstFailure.Label}': {firstFailure.FailureReason}", signatures);
    }
}

/// <summary>
/// Verifies HTTP message signatures (RFC 9421 Section 3.2): parses the
/// <c>Signature-Input</c>/<c>Signature</c> fields, re-assembles the signature
/// base from the message, resolves the key and checks the cryptographic
/// signature plus timestamp and coverage policy.
/// </summary>
public sealed class HttpMessageVerifier
{
    private readonly VerificationOptions _options;

    /// <summary>Creates a verifier with the given options.</summary>
    public HttpMessageVerifier(VerificationOptions options) => _options = options;

    /// <summary>
    /// Verifies the message's signatures. When <paramref name="label"/> is given only
    /// that signature is checked; otherwise all present signatures must verify.
    /// </summary>
    public async Task<VerificationResult> VerifyAsync(
        IHttpMessageContext message,
        string? label = null,
        CancellationToken cancellationToken = default)
    {
        SfDictionary signatureInputs;
        SfDictionary signatures;
        try
        {
            signatureInputs = ParseDictionaryField(message, "signature-input");
            signatures = ParseDictionaryField(message, "signature");
        }
        catch (SfParseException e)
        {
            return VerificationResult.Failure($"Malformed signature fields: {e.Message}");
        }

        if (signatureInputs.Count == 0)
        {
            return VerificationResult.Failure("The message carries no Signature-Input field.");
        }

        var selected = label is null
            ? signatureInputs.ToArray()
            : signatureInputs.Where(e => e.Key == label).ToArray();

        if (selected.Length == 0)
        {
            return VerificationResult.Failure($"The message carries no signature labeled '{label}'.");
        }

        var results = new List<SignatureVerification>(selected.Length);
        foreach (var (sigLabel, inputMember) in selected)
        {
            results.Add(await VerifyOneAsync(message, sigLabel, inputMember, signatures, cancellationToken).ConfigureAwait(false));
        }

        return VerificationResult.FromSignatures(results);
    }

    private async Task<SignatureVerification> VerifyOneAsync(
        IHttpMessageContext message,
        string label,
        SfMember inputMember,
        SfDictionary signatures,
        CancellationToken cancellationToken)
    {
        SignatureVerification Fail(string reason, SignatureParameters? parameters = null) =>
            new(label, false, reason, parameters);

        if (inputMember is not SfInnerList innerList)
        {
            return Fail("The Signature-Input member is not an inner list.");
        }

        if (signatures.Get(label) is not SfItem { Value: SfBytes signatureBytes })
        {
            return Fail("No matching byte-sequence member in the Signature field.");
        }

        SignatureParameters parameters;
        string signatureBase;
        try
        {
            parameters = SignatureParameters.FromSfInnerList(innerList);
            signatureBase = SignatureBaseBuilder.Build(message, parameters);
        }
        catch (HttpMessageSignatureException e)
        {
            return Fail(e.Message);
        }

        var timestampFailure = CheckTimestamps(parameters);
        if (timestampFailure is not null)
        {
            return Fail(timestampFailure, parameters);
        }

        foreach (var required in _options.RequiredComponents)
        {
            if (!parameters.Components.Contains(required))
            {
                return Fail($"The signature does not cover the required component {required}.", parameters);
            }
        }

        var algorithm = await _options.KeyResolver
            .ResolveAsync(parameters.KeyId, parameters.Algorithm, cancellationToken)
            .ConfigureAwait(false);
        if (algorithm is null)
        {
            return Fail($"Unknown key '{parameters.KeyId}'.", parameters);
        }

        // Downgrade protection: an advertised alg must match the key's algorithm.
        if (parameters.Algorithm is { } advertised && advertised != algorithm.Name)
        {
            return Fail($"The alg parameter '{advertised}' does not match the key's algorithm '{algorithm.Name}'.", parameters);
        }

        return algorithm.Verify(Encoding.UTF8.GetBytes(signatureBase), signatureBytes.Value.Span)
            ? new SignatureVerification(label, true, null, parameters)
            : Fail("The cryptographic signature does not match the signature base.", parameters);
    }

    private string? CheckTimestamps(SignatureParameters parameters)
    {
        var now = _options.TimeProvider.GetUtcNow();

        if (parameters.Created is { } created)
        {
            if (created - _options.ClockSkew > now)
            {
                return "The signature's created time lies in the future.";
            }

            if (_options.MaxAge is { } maxAge && now - created - _options.ClockSkew > maxAge)
            {
                return "The signature is older than the allowed maximum age.";
            }
        }
        else if (_options.RequireCreated)
        {
            return "The signature has no created parameter.";
        }

        if (parameters.Expires is { } expires && expires + _options.ClockSkew < now)
        {
            return "The signature has expired.";
        }

        return null;
    }

    private static SfDictionary ParseDictionaryField(IHttpMessageContext message, string fieldName)
    {
        var values = message.GetFieldValues(fieldName);
        return values.Count == 0
            ? new SfDictionary()
            : SfParser.ParseDictionary(string.Join(", ", values));
    }
}
