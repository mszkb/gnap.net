using System.Security.Cryptography;
using System.Text;

namespace Gnap.HttpMessageSignatures;

/// <summary>
/// Creates HTTP message signatures (RFC 9421 Section 3.1): builds the signature
/// base for the configured covered components, signs it, and produces the
/// <c>Signature-Input</c> and <c>Signature</c> field values.
/// </summary>
public sealed class HttpMessageSigner
{
    /// <summary>Creates a signer for the given algorithm-with-key.</summary>
    public HttpMessageSigner(SignatureAlgorithm algorithm)
    {
        ArgumentNullException.ThrowIfNull(algorithm);
        if (!algorithm.CanSign)
        {
            throw new ArgumentException("The algorithm has no private key material and cannot sign.", nameof(algorithm));
        }

        Algorithm = algorithm;
    }

    /// <summary>The signing algorithm bound to its key.</summary>
    public SignatureAlgorithm Algorithm { get; }

    /// <summary>The signature label used in the <c>Signature-Input</c> and <c>Signature</c> dictionaries.</summary>
    public string Label { get; init; } = "sig1";

    /// <summary>The <c>keyid</c> parameter identifying the key to the verifier.</summary>
    public string? KeyId { get; init; }

    /// <summary>The components to cover. Defaults to empty; covering at least the method and target is strongly recommended.</summary>
    public IReadOnlyList<SignatureComponent> CoveredComponents { get; init; } = [];

    /// <summary>Whether to add the <c>created</c> parameter. Defaults to <see langword="true"/>.</summary>
    public bool IncludeCreated { get; init; } = true;

    /// <summary>If set, the signature expires this long after creation (<c>expires</c> parameter).</summary>
    public TimeSpan? Lifetime { get; init; }

    /// <summary>Whether to advertise the algorithm via the <c>alg</c> parameter. Defaults to <see langword="false"/> (the verifier derives it from the key).</summary>
    public bool IncludeAlgorithm { get; init; }

    /// <summary>If set, a fresh random <c>nonce</c> of this many bytes (base64url) is added per signature.</summary>
    public int? NonceLength { get; init; }

    /// <summary>The application-specific <c>tag</c> parameter, if any.</summary>
    public string? Tag { get; init; }

    /// <summary>The clock used for <c>created</c>/<c>expires</c>; overridable for tests.</summary>
    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;

    /// <summary>Signs the message and returns the header values to attach.</summary>
    /// <exception cref="HttpMessageSignatureException">The signature base cannot be built.</exception>
    public SigningResult Sign(IHttpMessageContext message)
    {
        var parameters = new SignatureParameters().AddComponents(CoveredComponents);

        var now = TimeProvider.GetUtcNow();
        if (IncludeCreated)
        {
            parameters.WithCreated(now);
        }

        if (Lifetime is { } lifetime)
        {
            parameters.WithExpires(now + lifetime);
        }

        if (NonceLength is { } nonceLength)
        {
            parameters.WithNonce(Convert.ToBase64String(RandomNumberGenerator.GetBytes(nonceLength))
                .TrimEnd('=').Replace('+', '-').Replace('/', '_'));
        }

        if (IncludeAlgorithm)
        {
            parameters.WithAlgorithm(Algorithm.Name);
        }

        if (KeyId is not null)
        {
            parameters.WithKeyId(KeyId);
        }

        if (Tag is not null)
        {
            parameters.WithTag(Tag);
        }

        var signatureBase = SignatureBaseBuilder.Build(message, parameters);
        var signature = Algorithm.Sign(Encoding.UTF8.GetBytes(signatureBase));

        return new SigningResult(
            Label,
            $"{Label}={parameters.Serialize()}",
            $"{Label}=:{Convert.ToBase64String(signature)}:",
            signatureBase);
    }
}

/// <summary>The output of <see cref="HttpMessageSigner.Sign"/>.</summary>
/// <param name="Label">The signature label.</param>
/// <param name="SignatureInput">The value to append to the <c>Signature-Input</c> field.</param>
/// <param name="Signature">The value to append to the <c>Signature</c> field.</param>
/// <param name="SignatureBase">The canonical signature base that was signed (useful for debugging).</param>
public sealed record SigningResult(string Label, string SignatureInput, string Signature, string SignatureBase);

/// <summary>Extensions to attach signatures to <see cref="HttpRequestMessage"/> and <see cref="HttpResponseMessage"/>.</summary>
public static class HttpMessageSignerExtensions
{
    /// <summary>Signs the request and appends the <c>Signature-Input</c>/<c>Signature</c> headers.</summary>
    public static SigningResult Sign(this HttpMessageSigner signer, HttpRequestMessage request)
    {
        var result = signer.Sign(new HttpRequestMessageContext(request));
        request.Headers.TryAddWithoutValidation("Signature-Input", result.SignatureInput);
        request.Headers.TryAddWithoutValidation("Signature", result.Signature);
        return result;
    }

    /// <summary>Signs the response and appends the <c>Signature-Input</c>/<c>Signature</c> headers.</summary>
    public static SigningResult Sign(this HttpMessageSigner signer, HttpResponseMessage response)
    {
        var result = signer.Sign(new HttpResponseMessageContext(response));
        response.Headers.TryAddWithoutValidation("Signature-Input", result.SignatureInput);
        response.Headers.TryAddWithoutValidation("Signature", result.Signature);
        return result;
    }
}
