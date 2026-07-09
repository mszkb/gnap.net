namespace Gnap.HttpMessageSignatures;

/// <summary>
/// An <see cref="HttpClient"/> handler that signs every outgoing request and,
/// for requests with content, adds a <c>Content-Digest</c> field first so the
/// body can be covered by the signature.
/// </summary>
public sealed class HttpSignatureDelegatingHandler : DelegatingHandler
{
    private readonly HttpMessageSigner _signer;

    /// <summary>Creates the handler around a configured signer.</summary>
    public HttpSignatureDelegatingHandler(HttpMessageSigner signer, HttpMessageHandler? innerHandler = null)
    {
        ArgumentNullException.ThrowIfNull(signer);
        _signer = signer;
        if (innerHandler is not null)
        {
            InnerHandler = innerHandler;
        }
    }

    /// <summary>
    /// Whether to compute and attach a <c>Content-Digest</c> field for requests
    /// with content. Defaults to <see langword="true"/>. The request content is
    /// buffered to compute the digest.
    /// </summary>
    public bool AddContentDigest { get; init; } = true;

    /// <summary>The digest algorithm used for <c>Content-Digest</c>. Defaults to SHA-256.</summary>
    public ContentDigestAlgorithm DigestAlgorithm { get; init; } = ContentDigestAlgorithm.Sha256;

    /// <inheritdoc />
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (AddContentDigest && request.Content is not null && !request.Content.Headers.Contains("Content-Digest"))
        {
            var content = await request.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
            request.Content.Headers.TryAddWithoutValidation(
                "Content-Digest",
                ContentDigest.CreateHeaderValue(content, DigestAlgorithm));
        }

        _signer.Sign(request);
        return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }
}
