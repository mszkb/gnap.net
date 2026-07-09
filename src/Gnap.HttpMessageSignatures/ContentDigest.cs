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
        SfDictionary dictionary;
        try
        {
            dictionary = SfParser.ParseDictionary(headerValue);
        }
        catch (SfParseException)
        {
            return ContentDigestValidation.Malformed;
        }

        var supportedEntries = 0;
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

            supportedEntries++;
            if (!CryptographicOperations.FixedTimeEquals(Hash(algorithm, content), digest.Value.Span))
            {
                return ContentDigestValidation.Mismatch;
            }
        }

        return supportedEntries == 0 ? ContentDigestValidation.NoSupportedAlgorithm : ContentDigestValidation.Valid;
    }

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
