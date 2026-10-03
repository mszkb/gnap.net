using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Gnap.Client;
using Gnap.Core;

namespace Gnap.AspNetCore.Tests.Infrastructure;

/// <summary>Hand-crafted, signed protocol requests for negative tests.</summary>
internal static class RawRequests
{
    public static async Task<(HttpStatusCode Status, string Body)> SendSignedAsync(
        this AsHarness h,
        HttpMethod method,
        Uri uri,
        GnapClientKey? key,
        string? accessToken = null,
        string? json = null,
        TimeProvider? clock = null)
    {
        using var request = Create(method, uri, accessToken, json);
        if (key is not null)
        {
            await key.CreateProofer(clock ?? h.Time).AddProofAsync(request);
        }

        return await SendAsync(h.Http, request);
    }

    public static HttpRequestMessage Create(HttpMethod method, Uri uri, string? accessToken, string? json)
    {
        var request = new HttpRequestMessage(method, uri);
        if (json is not null)
        {
            request.Content = new ByteArrayContent(Encoding.UTF8.GetBytes(json));
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        }

        if (accessToken is not null)
        {
            GnapAuthorization.Apply(request, accessToken);
        }

        return request;
    }

    public static async Task<(HttpStatusCode Status, string Body)> SendAsync(HttpClient http, HttpRequestMessage request)
    {
        using var response = await http.SendAsync(request);
        return (response.StatusCode, await response.Content.ReadAsStringAsync());
    }

    /// <summary>Copies a request including its signature headers, for replay.</summary>
    public static async Task<HttpRequestMessage> CloneAsync(HttpRequestMessage original)
    {
        var copy = new HttpRequestMessage(original.Method, original.RequestUri);
        foreach (var header in original.Headers)
        {
            copy.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }

        if (original.Content is not null)
        {
            copy.Content = new ByteArrayContent(await original.Content.ReadAsByteArrayAsync());
            foreach (var header in original.Content.Headers)
            {
                copy.Content.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
        }

        return copy;
    }
}

/// <summary>A fixed clock, e.g. for signatures created outside the acceptance window.</summary>
internal sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
{
    public override DateTimeOffset GetUtcNow() => now;
}
