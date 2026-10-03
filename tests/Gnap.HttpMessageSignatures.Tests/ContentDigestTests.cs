using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace Gnap.HttpMessageSignatures.Tests;

/// <summary>Content-Digest creation and validation per RFC 9530.</summary>
public class ContentDigestTests
{
    private static readonly byte[] HelloWorldJson = Encoding.UTF8.GetBytes("{\"hello\": \"world\"}");

    [Fact]
    public void Sha256HeaderValue_MatchesRfc9530Example()
    {
        var value = ContentDigest.CreateHeaderValue(HelloWorldJson, ContentDigestAlgorithm.Sha256);

        Assert.Equal("sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:", value);
    }

    [Fact]
    public void Sha512HeaderValue_MatchesRfc9421TestRequest()
    {
        var value = ContentDigest.CreateHeaderValue(HelloWorldJson, ContentDigestAlgorithm.Sha512);

        Assert.Equal(Rfc9421TestVectors.RequestContentDigest.Replace(" ", ""), value.Replace(" ", ""));
        Assert.Equal(ContentDigestValidation.Valid, ContentDigest.Validate(value, HelloWorldJson));
    }

    [Fact]
    public void MultipleAlgorithms_AllMustMatch()
    {
        var value = ContentDigest.CreateHeaderValue(HelloWorldJson, ContentDigestAlgorithm.Sha256, ContentDigestAlgorithm.Sha512);

        Assert.Equal(ContentDigestValidation.Valid, ContentDigest.Validate(value, HelloWorldJson));
        Assert.Equal(ContentDigestValidation.Mismatch, ContentDigest.Validate(value, Encoding.UTF8.GetBytes("{}")));
    }

    [Fact]
    public void TamperedContent_IsDetected()
    {
        var value = ContentDigest.CreateHeaderValue(HelloWorldJson);

        Assert.Equal(ContentDigestValidation.Mismatch, ContentDigest.Validate(value, Encoding.UTF8.GetBytes("{\"hello\": \"World\"}")));
    }

    [Fact]
    public void UnsupportedAlgorithmOnly_IsReported()
    {
        Assert.Equal(
            ContentDigestValidation.NoSupportedAlgorithm,
            ContentDigest.Validate("md5=:XrY7u+Ae7tCTyyK7j1rNww==:", HelloWorldJson));
    }

    [Fact]
    public void MalformedHeader_IsReported()
    {
        Assert.Equal(ContentDigestValidation.Malformed, ContentDigest.Validate("sha-256=notbase64", HelloWorldJson));
        Assert.Equal(ContentDigestValidation.Malformed, ContentDigest.Validate("sha-256=\"a string\"", HelloWorldJson));
    }

    [Fact]
    public void DefaultAlgorithm_IsSha256()
    {
        Assert.StartsWith("sha-256=:", ContentDigest.CreateHeaderValue(HelloWorldJson), StringComparison.Ordinal);
    }

    [Fact]
    public async Task StreamingValidation_MatchesSpanValidation()
    {
        var value = ContentDigest.CreateHeaderValue(HelloWorldJson, ContentDigestAlgorithm.Sha256, ContentDigestAlgorithm.Sha512);

        Assert.Equal(ContentDigestValidation.Valid, await ContentDigest.ValidateAsync(value, new MemoryStream(HelloWorldJson)));
        Assert.Equal(ContentDigestValidation.Mismatch, await ContentDigest.ValidateAsync(value, new MemoryStream(Encoding.UTF8.GetBytes("{}"))));
        Assert.Equal(ContentDigestValidation.Malformed, await ContentDigest.ValidateAsync("sha-256=notbase64", new MemoryStream(HelloWorldJson)));
        Assert.Equal(
            ContentDigestValidation.NoSupportedAlgorithm,
            await ContentDigest.ValidateAsync("md5=:XrY7u+Ae7tCTyyK7j1rNww==:", new MemoryStream(HelloWorldJson)));
    }

    [Fact]
    public async Task StreamingValidation_StopsReadingPastTheLimit()
    {
        var value = ContentDigest.CreateHeaderValue(HelloWorldJson);
        var content = new MemoryStream(new byte[100_000]);

        var result = await ContentDigest.ValidateAsync(value, content, maxContentLength: 10);

        Assert.Equal(ContentDigestValidation.ContentTooLarge, result);
        Assert.Equal(11, content.Position);
    }

    [Fact]
    public async Task StreamingValidation_ContentExactlyAtLimit_IsValidated()
    {
        var value = ContentDigest.CreateHeaderValue(HelloWorldJson);

        var result = await ContentDigest.ValidateAsync(value, new MemoryStream(HelloWorldJson), maxContentLength: HelloWorldJson.Length);

        Assert.Equal(ContentDigestValidation.Valid, result);
    }

    [Fact]
    public async Task StreamingValidation_RejectsInvalidArguments()
    {
        var value = ContentDigest.CreateHeaderValue(HelloWorldJson);

        await Assert.ThrowsAsync<ArgumentNullException>("content", () => ContentDigest.ValidateAsync(value, null!));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            "maxContentLength",
            () => ContentDigest.ValidateAsync(value, new MemoryStream(HelloWorldJson), maxContentLength: -1));
    }

    [Fact]
    public async Task StreamingValidation_WithShortReads_StopsOneBytePastTheLimit()
    {
        // A stream that hands out at most 3 bytes per read forces several loop
        // iterations, so the remaining budget must shrink with every read.
        var value = ContentDigest.CreateHeaderValue(HelloWorldJson);
        var content = new ChunkedStream(new byte[1000], chunkSize: 3);

        var result = await ContentDigest.ValidateAsync(value, content, maxContentLength: 10);

        Assert.Equal(ContentDigestValidation.ContentTooLarge, result);
        Assert.Equal(11, content.Position);
    }

    [Fact]
    public async Task StreamingValidation_ContentExactlyOneBufferLong_IsValidated()
    {
        // 16 KiB is the internal buffer size: the limit equals the buffer length exactly.
        var content = RandomNumberGenerator.GetBytes(16 * 1024);
        var value = ContentDigest.CreateHeaderValue(content);

        var result = await ContentDigest.ValidateAsync(value, new MemoryStream(content), maxContentLength: content.Length);

        Assert.Equal(ContentDigestValidation.Valid, result);
    }

    private sealed class ChunkedStream(byte[] data, int chunkSize) : MemoryStream(data)
    {
        public override int Read(byte[] buffer, int offset, int count) => base.Read(buffer, offset, Math.Min(count, chunkSize));

        public override int Read(Span<byte> buffer) => base.Read(buffer[..Math.Min(buffer.Length, chunkSize)]);

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            base.ReadAsync(buffer[..Math.Min(buffer.Length, chunkSize)], cancellationToken);
    }
}
