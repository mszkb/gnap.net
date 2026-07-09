using Gnap.Core.Keys;
using Gnap.HttpMessageSignatures;
using Gnap.HttpMessageSignatures.StructuredFields;

namespace Gnap.Core.Proofing;

/// <summary>
/// Validates <c>httpsig</c> key proofs (RFC 9635 Section 7.3.1): the message must
/// carry at least one signature by the expected key that covers <c>@method</c>,
/// <c>@target-uri</c>, <c>content-digest</c> for messages with content and
/// <c>authorization</c> when present, with <c>tag="gnap"</c>, a fresh
/// <c>created</c> timestamp, no advertised <c>alg</c> parameter, a valid
/// <c>Content-Digest</c>, and an unseen <c>nonce</c> when a store is configured.
/// </summary>
public sealed class HttpSigKeyProofValidator : IKeyProofValidator
{
    /// <inheritdoc />
    public string Method => ProofMethod.Methods.HttpSig;

    /// <summary>Tolerated clock difference for <c>created</c> checks. Defaults to 5 minutes.</summary>
    public TimeSpan ClockSkew { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>Maximum accepted signature age. Defaults to 5 minutes.</summary>
    public TimeSpan MaxAge { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// The replay protection store. When set, every accepted signature's nonce is
    /// registered and repeated nonces are rejected. Strongly recommended for servers.
    /// </summary>
    public INonceStore? NonceStore { get; init; }

    /// <summary>How long registered nonces are remembered. Defaults to 15 minutes.</summary>
    public TimeSpan NonceLifetime { get; init; } = TimeSpan.FromMinutes(15);

    /// <summary>Whether a <c>nonce</c> parameter is required (the RFC says SHOULD). Defaults to <see langword="false"/>.</summary>
    public bool RequireNonce { get; init; }

    /// <summary>
    /// When set, the signature's <c>keyid</c> must equal this value. Use the JWK's
    /// <c>kid</c> when the client presented its key as a JWK.
    /// </summary>
    public string? ExpectedKeyId { get; init; }

    /// <summary>The clock used for timestamp checks; overridable for tests.</summary>
    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;

    /// <inheritdoc />
    public async Task<KeyProofResult> ValidateAsync(KeyProofContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        var message = context.Message;

        var hasContent = context.Content is { IsEmpty: false };
        if (hasContent)
        {
            var digestValues = message.GetFieldValues("content-digest");
            if (digestValues.Count == 0)
            {
                return KeyProofResult.Failure("The message has content but no Content-Digest field.");
            }

            var validation = ContentDigest.Validate(string.Join(", ", digestValues), context.Content!.Value.Span);
            if (validation != ContentDigestValidation.Valid)
            {
                return KeyProofResult.Failure($"Content-Digest validation failed: {validation}.");
            }
        }

        var requiredComponents = new List<SignatureComponent>
        {
            SignatureComponent.Method,
            SignatureComponent.TargetUri,
        };

        if (hasContent)
        {
            requiredComponents.Add(SignatureComponent.ContentDigest);
        }

        if (message.GetFieldValues("authorization").Count > 0)
        {
            requiredComponents.Add(SignatureComponent.Field("authorization"));
        }

        IReadOnlyList<string> labels;
        try
        {
            var inputValues = message.GetFieldValues("signature-input");
            labels = inputValues.Count == 0
                ? []
                : SfParser.ParseDictionary(string.Join(", ", inputValues)).Select(m => m.Key).ToArray();
        }
        catch (SfParseException e)
        {
            return KeyProofResult.Failure($"Malformed Signature-Input field: {e.Message}");
        }

        if (labels.Count == 0)
        {
            return KeyProofResult.Failure("The message carries no HTTP message signature.");
        }

        var verifier = new HttpMessageVerifier(new VerificationOptions
        {
            KeyResolver = new FixedKeyResolver(context.Key),
            ClockSkew = ClockSkew,
            MaxAge = MaxAge,
            RequireCreated = true,
            RequiredComponents = requiredComponents,
            TimeProvider = TimeProvider,
        });

        // Section 7.3.1: examine all signatures until at least one acceptable
        // signature is found.
        string? lastFailure = null;
        foreach (var label in labels)
        {
            var verification = await verifier.VerifyAsync(message, label, cancellationToken).ConfigureAwait(false);
            if (!verification.Succeeded)
            {
                lastFailure = verification.FailureReason;
                continue;
            }

            var parameters = verification.Signatures[0].Parameters!;
            if (parameters.Tag != GnapConstants.HttpSignatureTag)
            {
                lastFailure = $"Signature '{label}': the tag parameter is not '{GnapConstants.HttpSignatureTag}'.";
                continue;
            }

            if (parameters.Algorithm is not null)
            {
                lastFailure = $"Signature '{label}': the alg parameter must not be included in GNAP signatures.";
                continue;
            }

            if (ExpectedKeyId is not null && parameters.KeyId != ExpectedKeyId)
            {
                lastFailure = $"Signature '{label}': the keyid does not match the presented key.";
                continue;
            }

            if (parameters.Nonce is { } nonce)
            {
                if (NonceStore is not null)
                {
                    var expires = TimeProvider.GetUtcNow() + NonceLifetime;
                    var scopedNonce = $"{parameters.KeyId}\n{nonce}";
                    if (!await NonceStore.TryRegisterAsync(scopedNonce, expires, cancellationToken).ConfigureAwait(false))
                    {
                        lastFailure = $"Signature '{label}': the nonce was already used (replay).";
                        continue;
                    }
                }
            }
            else if (RequireNonce)
            {
                lastFailure = $"Signature '{label}': a nonce parameter is required.";
                continue;
            }

            return KeyProofResult.Success;
        }

        return KeyProofResult.Failure(lastFailure ?? "The message carries no acceptable signature.");
    }

    private sealed class FixedKeyResolver(SignatureAlgorithm key) : IVerificationKeyResolver
    {
        public ValueTask<SignatureAlgorithm?> ResolveAsync(string? keyId, string? algorithm, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<SignatureAlgorithm?>(key);
    }
}
