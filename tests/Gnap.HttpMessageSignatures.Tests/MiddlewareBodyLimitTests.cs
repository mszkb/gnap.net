using System.Net;
using System.Text;
using Gnap.HttpMessageSignatures.AspNetCore;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Gnap.HttpMessageSignatures.Tests;

/// <summary>
/// The digest validation buffer limit must hold for bodies without a
/// <c>Content-Length</c> (chunked transfer coding), and unauthenticated
/// requests must not cause any body buffering at all.
/// </summary>
public sealed class MiddlewareBodyLimitTests : IAsyncLifetime
{
    private const int Limit = 4096;
    private const string KeyId = "limit-client";

    private static readonly SignatureComponent[] Components =
    [
        SignatureComponent.Method,
        SignatureComponent.TargetUri,
        SignatureComponent.ContentDigest,
    ];

    private readonly SignatureAlgorithm _clientKey = RoundtripTests.CreateFreshKey("ed25519");
    private IHost _host = null!;

    public async Task InitializeAsync()
    {
        _host = await new HostBuilder()
            .ConfigureWebHost(webHost => webHost
                .UseTestServer()
                .ConfigureServices(services => services.AddHttpMessageSignatureVerification(ConfigureOptions))
                .Configure(app =>
                {
                    app.UseHttpMessageSignatureVerification();
                    app.Run(async context =>
                    {
                        // Echo the body length to prove the endpoint can still read it.
                        using var reader = new StreamReader(context.Request.Body);
                        var body = await reader.ReadToEndAsync();
                        await context.Response.WriteAsync($"read {body.Length}");
                    });
                }))
            .StartAsync();
    }

    public async Task DisposeAsync()
    {
        await _host.StopAsync();
        _host.Dispose();
    }

    private void ConfigureOptions(HttpMessageSignatureOptions options)
    {
        options.KeyResolver = new StaticKeyResolver().Add(KeyId, _clientKey);
        options.MaxBufferedContentLength = Limit;
    }

    private HttpRequestMessage CreateSignedChunkedRequest(byte[] body, Stream? bodyStream = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, new Uri(_host.GetTestServer().BaseAddress, "/api/data"))
        {
            Content = new StreamContent(bodyStream ?? new CountingStream(body.Length)),
        };
        request.Content.Headers.TryAddWithoutValidation("Content-Digest", ContentDigest.CreateHeaderValue(body));
        request.Headers.TransferEncodingChunked = true;
        new HttpMessageSigner(_clientKey) { KeyId = KeyId, CoveredComponents = Components }.Sign(request);
        return request;
    }

    [Fact]
    public async Task ChunkedBodyWithinLimit_AndValidDigest_IsAccepted()
    {
        var body = CountingStream.Content(Limit);
        using var client = new HttpClient(_host.GetTestServer().CreateHandler());

        var response = await client.SendAsync(CreateSignedChunkedRequest(body));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal($"read {Limit}", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task ChunkedBodyOverLimit_IsRejectedWith401()
    {
        var body = CountingStream.Content(Limit + 1);
        using var client = new HttpClient(_host.GetTestServer().CreateHandler());

        var response = await client.SendAsync(CreateSignedChunkedRequest(body));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ChunkedBodyOverLimit_IsNotBufferedBeyondLimit()
    {
        const int bodyLength = 10 * 1024 * 1024;
        var source = new CountingStream(bodyLength);
        var context = CreateSignedChunkedContext(source, signed: true);

        await CreateMiddleware().InvokeAsync(context);

        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
        Assert.InRange(source.BytesRead, Limit, Limit + 1);
    }

    [Fact]
    public async Task UnsignedChunkedBody_IsRejectedWithoutReadingTheBody()
    {
        var source = new CountingStream(10 * 1024 * 1024);
        var context = CreateSignedChunkedContext(source, signed: false);

        await CreateMiddleware().InvokeAsync(context);

        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
        Assert.Equal(0, source.BytesRead);
    }

    [Fact]
    public async Task ChunkedBodyWithinLimit_IsRewoundForTheEndpoint()
    {
        var source = new CountingStream(Limit);
        var context = CreateSignedChunkedContext(source, signed: true);
        long endpointRead = -1;

        var middleware = CreateMiddleware(async ctx =>
        {
            using var copy = new MemoryStream();
            await ctx.Request.Body.CopyToAsync(copy);
            endpointRead = copy.Length;
        });
        await middleware.InvokeAsync(context);

        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
        Assert.Equal(Limit, endpointRead);
    }

    private HttpMessageSignatureMiddleware CreateMiddleware(RequestDelegate? next = null)
    {
        var options = new HttpMessageSignatureOptions();
        ConfigureOptions(options);
        return new HttpMessageSignatureMiddleware(
            next ?? (_ => Task.CompletedTask),
            Options.Create(options),
            NullLogger<HttpMessageSignatureMiddleware>.Instance);
    }

    private DefaultHttpContext CreateSignedChunkedContext(CountingStream source, bool signed)
    {
        var digest = ContentDigest.CreateHeaderValue(CountingStream.Content(source.BodyLength));
        var context = new DefaultHttpContext();
        context.Request.Method = "POST";
        context.Request.Scheme = "http";
        context.Request.Host = new HostString("localhost");
        context.Request.Path = "/api/data";
        context.Request.Headers.TransferEncoding = "chunked";
        context.Request.Headers["Content-Digest"] = digest;
        context.Request.Body = source;

        if (signed)
        {
            var message = new HttpRequestMessage(HttpMethod.Post, "http://localhost/api/data")
            {
                Content = new ByteArrayContent([]),
            };
            message.Content.Headers.TryAddWithoutValidation("Content-Digest", digest);
            var signature = new HttpMessageSigner(_clientKey) { KeyId = KeyId, CoveredComponents = Components }.Sign(message);
            context.Request.Headers["Signature-Input"] = signature.SignatureInput;
            context.Request.Headers["Signature"] = signature.Signature;
        }

        return context;
    }

    /// <summary>A non-seekable body of deterministic bytes that records how much was read.</summary>
    private sealed class CountingStream(long length) : Stream
    {
        public long BodyLength => length;

        public long BytesRead { get; private set; }

        public static byte[] Content(long length)
        {
            var content = new byte[length];
            for (var i = 0; i < content.Length; i++)
            {
                content[i] = (byte)('a' + (i % 26));
            }

            return content;
        }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var n = (int)Math.Min(count, length - BytesRead);
            for (var i = 0; i < n; i++)
            {
                buffer[offset + i] = (byte)('a' + ((BytesRead + i) % 26));
            }

            BytesRead += n;
            return n;
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            Task.FromResult(Read(buffer, offset, count));

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            var array = new byte[buffer.Length];
            var n = Read(array, 0, array.Length);
            array.AsSpan(0, n).CopyTo(buffer.Span);
            return ValueTask.FromResult(n);
        }

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
