using System.Security.Cryptography;
using Gnap.HttpMessageSignatures.StructuredFields;

namespace Gnap.HttpMessageSignatures;

/// <summary>The digest algorithms of RFC 9530 supported by this library.</summary>
public enum ContentDigestAlgorithm
{
    /// <summary>SHA-256 (<c>sha-256</c>).</summary>
    Sha256,

    /// <summary>SHA-512 (<c>sha-512</c>).</summary>
    Sha512,
}

/// <summary>The outcome of validating a <c>Content-Digest</c> field against actual content.</summary>
public enum ContentDigestValidation
{
    /// <summary>Every supported digest entry matches the content.</summary>
    Valid,

    /// <summary>At least one supported digest entry does not match the content.</summary>
    Mismatch,

    /// <summary>The field contains no entry with a supported algorithm.</summary>
    NoSupportedAlgorithm,

    /// <summary>The field value is not a valid RFC 9530 dictionary.</summary>
    Malformed,

    /// <summary>
    /// The content exceeds the maximum length allowed for streaming validation;
    /// reading stopped at the limit and the digest was not checked.
    /// </summary>
    ContentTooLarge,
}

/// <summary>Creates and validates <c>Content-Digest</c> field values (RFC 9530).</summary>
public static class ContentDigest
{
    /// <summary>Computes a <c>Content-Digest</c> field value for the given content.</summary>
    public static string CreateHeaderValue(ReadOnlySpan<byte> content, params ContentDigestAlgorithm[] algorithms)
    {
        if (algorithms.Length == 0)
        {
            algorithms = [ContentDigestAlgorithm.Sha256];
        }

        var dictionary = new SfDictionary();
        foreach (var algorithm in algorithms)
        {
            dictionary.Add(GetName(algorithm), new SfItem(new SfBytes(Hash(algorithm, content))));
        }

        return dictionary.ToString();
    }

    /// <summary>
    /// Validates a received <c>Content-Digest</c> field value against the actual
    /// content. Every entry with a supported algorithm must match; unsupported
    /// algorithms are ignored unless no supported entry exists at all.
    /// </summary>
    public static ContentDigestValidation Validate(string headerValue, ReadOnlySpan<byte> content)
    {
        var parse = TryParse(headerValue, out var entries);
        if (parse is not ContentDigestValidation.Valid)
        {
            return parse;
        }

        foreach (var (algorithm, expected) in entries)
        {
            if (!CryptographicOperations.FixedTimeEquals(Hash(algorithm, content), expected.Span))
            {
                return ContentDigestValidation.Mismatch;
            }
        }

        return ContentDigestValidation.Valid;
    }

    /// <summary>
    /// Validates a received <c>Content-Digest</c> field value against content read
    /// from <paramref name="content"/>, hashing incrementally so the content is
    /// never copied into an intermediate buffer. The field is parsed first, so a
    /// malformed or unsupported field is reported without reading any content.
    /// Reading stops as soon as more than <paramref name="maxContentLength"/>
    /// bytes have been seen, in which case
    /// <see cref="ContentDigestValidation.ContentTooLarge"/> is returned.
    /// </summary>
    public static async Task<ContentDigestValidation> ValidateAsync(
        string headerValue,
        Stream content,
        long maxContentLength = long.MaxValue,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(content);
        ArgumentOutOfRangeException.ThrowIfNegative(maxContentLength);

        var parse = TryParse(headerValue, out var entries);
        if (parse is not ContentDigestValidation.Valid)
        {
            return parse;
        }

        var hashes = new IncrementalHash[entries.Count];
        try
        {
            for (var i = 0; i < entries.Count; i++)
            {
                hashes[i] = IncrementalHash.CreateHash(GetHashAlgorithmName(entries[i].Algorithm));
            }

            var buffer = new byte[16 * 1024];
            long total = 0;
            while (true)
            {
                // Never request more than one byte past the limit, so an oversized
                // body is detected without reading (or buffering) much beyond it.
                var remaining = maxContentLength - total;
                var toRead = remaining >= buffer.Length ? buffer.Length : (int)remaining + 1;
                var read = await content.ReadAsync(buffer.AsMemory(0, toRead), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                total += read;
                if (total > maxContentLength)
                {
                    return ContentDigestValidation.ContentTooLarge;
                }

                foreach (var hash in hashes)
                {
                    hash.AppendData(buffer, 0, read);
                }
            }

            for (var i = 0; i < entries.Count; i++)
            {
                if (!CryptographicOperations.FixedTimeEquals(hashes[i].GetHashAndReset(), entries[i].Expected.Span))
                {
                    return ContentDigestValidation.Mismatch;
                }
            }

            return ContentDigestValidation.Valid;
        }
        finally
        {
            foreach (var hash in hashes)
            {
                hash?.Dispose();
            }
        }
    }

    private static ContentDigestValidation TryParse(
        string headerValue,
        out List<(ContentDigestAlgorithm Algorithm, ReadOnlyMemory<byte> Expected)> entries)
    {
        entries = [];
        SfDictionary dictionary;
        try
        {
            dictionary = SfParser.ParseDictionary(headerValue);
        }
        catch (SfParseException)
        {
            return ContentDigestValidation.Malformed;
        }

        foreach (var (name, member) in dictionary)
        {
            if (TryGetAlgorithm(name) is not { } algorithm)
            {
                continue;
            }

            if (member is not SfItem { Value: SfBytes digest })
            {
                return ContentDigestValidation.Malformed;
            }

            entries.Add((algorithm, digest.Value));
        }

        return entries.Count == 0 ? ContentDigestValidation.NoSupportedAlgorithm : ContentDigestValidation.Valid;
    }

    private static HashAlgorithmName GetHashAlgorithmName(ContentDigestAlgorithm algorithm) => algorithm switch
    {
        ContentDigestAlgorithm.Sha256 => HashAlgorithmName.SHA256,
        ContentDigestAlgorithm.Sha512 => HashAlgorithmName.SHA512,
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
    };

    private static string GetName(ContentDigestAlgorithm algorithm) => algorithm switch
    {
        ContentDigestAlgorithm.Sha256 => "sha-256",
        ContentDigestAlgorithm.Sha512 => "sha-512",
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
    };

    private static ContentDigestAlgorithm? TryGetAlgorithm(string name) => name switch
    {
        "sha-256" => ContentDigestAlgorithm.Sha256,
        "sha-512" => ContentDigestAlgorithm.Sha512,
        _ => null,
    };

    private static byte[] Hash(ContentDigestAlgorithm algorithm, ReadOnlySpan<byte> content) => algorithm switch
    {
        ContentDigestAlgorithm.Sha256 => SHA256.HashData(content),
        ContentDigestAlgorithm.Sha512 => SHA512.HashData(content),
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
    };
}
