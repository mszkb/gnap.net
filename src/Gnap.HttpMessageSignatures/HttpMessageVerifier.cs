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

    /// <summary>
    /// The replay protection store (RFC 9421 Section 7.2.2). When set, the <c>nonce</c>
    /// of every signature is recorded, scoped by <c>keyid</c>, and a nonce seen again
    /// within its acceptance window is rejected as a replay. Nonces are recorded only
    /// after all selected signatures verified, so invalid messages cannot "burn" them.
    /// Signatures without a nonce are not replay-checked unless <see cref="RequireNonce"/> is set.
    /// </summary>
    public INonceStore? NonceStore { get; init; }

    /// <summary>Whether every signature must carry a <c>nonce</c> parameter. Defaults to <see langword="false"/>.</summary>
    public bool RequireNonce { get; init; }

    /// <summary>
    /// How long a nonce is remembered when the signature's acceptance window is
    /// unbounded, i.e. neither <see cref="MaxAge"/> (with <c>created</c>) nor an
    /// <c>expires</c> parameter limits it. Otherwise nonces are kept exactly until
    /// the window ends (<c>created + MaxAge + ClockSkew</c> or <c>expires + ClockSkew</c>).
    /// Defaults to 15 minutes. Configure <see cref="MaxAge"/> for full replay prevention.
    /// </summary>
    public TimeSpan NonceRetention { get; init; } = TimeSpan.FromMinutes(15);

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

        // Replay check last: a nonce is only recorded once every selected signature
        // verified cryptographically, so an attacker cannot burn nonces with forgeries.
        if (_options.NonceStore is { } nonceStore && results.TrueForAll(r => r.Succeeded))
        {
            for (var i = 0; i < results.Count; i++)
            {
                var parameters = results[i].Parameters!;
                if (parameters.Nonce is not { } nonce)
                {
                    continue;
                }

                var accepted = await nonceStore
                    .TryAddAsync(parameters.KeyId ?? string.Empty, nonce, GetNonceExpiry(parameters), cancellationToken)
                    .ConfigureAwait(false);
                if (!accepted)
                {
                    results[i] = new SignatureVerification(results[i].Label, false, "The nonce was already used (replay).", parameters);
                }
            }
        }

        return VerificationResult.FromSignatures(results);
    }

    /// <summary>The end of the window in which <see cref="CheckTimestamps"/> would still accept the signature.</summary>
    private DateTimeOffset GetNonceExpiry(SignatureParameters parameters)
    {
        var now = _options.TimeProvider.GetUtcNow();
        DateTimeOffset? windowEnd = null;

        if (parameters.Created is { } created && _options.MaxAge is { } maxAge)
        {
            windowEnd = created + maxAge + _options.ClockSkew;
        }

        if (parameters.Expires is { } expires)
        {
            var expiresEnd = expires + _options.ClockSkew;
            // Stryker disable once Equality : '<' vs '<=' is equivalent here, both pick the same instant when end == expiresEnd.
            windowEnd = windowEnd is { } end && end < expiresEnd ? end : expiresEnd;
        }

        // The timestamp checks accept a signature up to and including the window's
        // end, so the entry must outlive that instant by one tick.
        return windowEnd is { } inclusiveEnd
            ? inclusiveEnd.AddTicks(1)
            : now + _options.NonceRetention;
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

        if (_options.RequireNonce && parameters.Nonce is null)
        {
            return Fail("The signature has no nonce parameter.", parameters);
        }

        foreach (var required in _options.RequiredComponents)
        {
            if (!parameters.Components.Contains(required))
            {
                return Fail($"The signature does not cover the required component {required}.", parameters);
            }
        }

        // Stryker disable once Boolean : ConfigureAwait(true/false) only changes the continuation context, which tests cannot observe.
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
        // An absent field joins to the empty string, which parses as an empty dictionary.
        return SfParser.ParseDictionary(string.Join(", ", message.GetFieldValues(fieldName)));
    }
}
