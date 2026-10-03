using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Gnap.Client.Interaction;
using Gnap.Client.Tests.Infrastructure;
using Gnap.Core.Models;
using Xunit;

namespace Gnap.Client.Tests;

public class ErrorHandlingTests
{
    public static TheoryData<string> AllRegisteredErrorCodes() =>
    [
        "invalid_request", "invalid_client", "invalid_interaction", "invalid_flag", "invalid_rotation",
        "key_rotation_not_supported", "invalid_continuation", "user_denied", "request_denied",
        "unknown_user", "unknown_interaction", "too_fast", "too_many_attempts",
    ];

    [Theory]
    [MemberData(nameof(AllRegisteredErrorCodes))]
    public async Task EveryRegisteredErrorCode_SurfacesTyped(string code)
    {
        using var h = ClientHarness.Create();
        h.As.FailNext("/tx", new GnapErrorCode(code));

        var e = await Assert.ThrowsAsync<GnapProtocolException>(
            () => h.Client.RequestAccessAsync([AccessRight.ForReference("photo-api")]));

        Assert.Equal(new GnapErrorCode(code), e.Code);
        Assert.Equal(HttpStatusCode.BadRequest, e.StatusCode);
        Assert.Equal($"scripted {code}", e.Error.Description);
    }

    [Fact]
    public async Task ErrorInStringForm_IsTyped()
    {
        using var h = ClientHarness.Create();
        h.As.FailNext("/tx", GnapErrorCode.InvalidRequest, asObject: false);

        var e = await Assert.ThrowsAsync<GnapProtocolException>(
            () => h.Client.RequestAccessAsync([AccessRight.ForReference("photo-api")]));

        Assert.Equal(GnapErrorCode.InvalidRequest, e.Code);
        Assert.Null(e.Error.Description);
    }

    [Fact]
    public async Task InvalidClient_WhenSignatureDoesNotMatchPresentedKey()
    {
        using var h = ClientHarness.Create();
        // Present one key, sign with another: the AS's verifier must reject it.
        var other = ClientHarness.NewEcKey(h.Jwk.Kid!);
        h.Client.UseClientKey(new GnapClientKey(other.ToSignatureAlgorithm(), h.Key.PresentedKey, h.Key.KeyId));

        var e = await Assert.ThrowsAsync<GnapProtocolException>(
            () => h.Client.RequestAccessAsync([AccessRight.ForReference("photo-api")]));

        Assert.Equal(GnapErrorCode.InvalidClient, e.Code);
        Assert.Single(h.As.ProofFailures);
    }

    [Fact]
    public async Task UserDenied_DuringPolling()
    {
        using var h = ClientHarness.Create();
        var handler = GnapInteractionHandler.UserCode((_, _) =>
        {
            h.As.Deny();
            return ValueTask.CompletedTask;
        });

        var e = await Assert.ThrowsAsync<GnapProtocolException>(
            () => h.Client.RequestAccessAsync(ClientHarness.PhotoRequest(), handler));

        Assert.Equal(GnapErrorCode.UserDenied, e.Code);
        h.AssertAllRequestsVerified(atLeast: 2);
    }

    [Fact]
    public async Task UserDenied_AfterRedirect()
    {
        using var h = ClientHarness.Create();
        var handler = GnapInteractionHandler.Redirect(new Uri("https://client.example/cb"), (_, _) =>
        {
            var redirect = h.As.ApproveAndRedirect();
            h.As.Deny();
            return ValueTask.FromResult(redirect);
        });

        var e = await Assert.ThrowsAsync<GnapProtocolException>(
            () => h.Client.RequestAccessAsync(ClientHarness.PhotoRequest(), handler));
        Assert.Equal(GnapErrorCode.UserDenied, e.Code);
    }

    [Fact]
    public async Task TooFast_BacksOffExponentiallyAndRecovers()
    {
        using var h = ClientHarness.Create();
        h.As.ContinueWait = 2;
        var handler = GnapInteractionHandler.UserCode((_, _) =>
        {
            h.As.Approve();
            return ValueTask.CompletedTask;
        });
        h.As.FailNext("/continue/", GnapErrorCode.TooFast);
        h.As.FailNext("/continue/", GnapErrorCode.TooFast);

        var result = await h.Client.RequestAccessAsync(ClientHarness.PhotoRequest(), handler);

        Assert.NotNull(result.AccessToken);
        // Initial wait 2 s, then back-off 4 s and 8 s after each too_fast.
        Assert.Equal([TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(4), TimeSpan.FromSeconds(8)], h.Time.Delays);
    }

    [Fact]
    public async Task TooFast_BackOffIsBounded()
    {
        using var h = ClientHarness.Create(o => o.MaxPollingInterval = TimeSpan.FromSeconds(3));
        h.As.ContinueWait = 2;
        var handler = GnapInteractionHandler.UserCode((_, _) =>
        {
            h.As.Approve();
            return ValueTask.CompletedTask;
        });
        h.As.FailNext("/continue/", GnapErrorCode.TooFast);
        h.As.FailNext("/continue/", GnapErrorCode.TooFast);

        await h.Client.RequestAccessAsync(ClientHarness.PhotoRequest(), handler);

        Assert.Equal([TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(3), TimeSpan.FromSeconds(3)], h.Time.Delays);
    }

    [Fact]
    public async Task Polling_GivesUpAfterMaxDuration()
    {
        using var h = ClientHarness.Create(o => o.MaxPollingDuration = TimeSpan.FromSeconds(30));
        h.As.ContinueWait = 10;
        var handler = GnapInteractionHandler.UserCode((_, _) => ValueTask.CompletedTask); // never approved

        var e = await Assert.ThrowsAsync<GnapClientException>(
            () => h.Client.RequestAccessAsync(ClientHarness.PhotoRequest(), handler));
        Assert.Contains("polling limit", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task UnknownInteraction_OnContinuation_IsTyped()
    {
        using var h = ClientHarness.Create();
        var handler = GnapInteractionHandler.Redirect(new Uri("https://client.example/cb"), (_, _) =>
        {
            h.As.FailNext("/continue/", GnapErrorCode.UnknownInteraction);
            return ValueTask.FromResult(h.As.ApproveAndRedirect());
        });

        var e = await Assert.ThrowsAsync<GnapProtocolException>(
            () => h.Client.RequestAccessAsync(ClientHarness.PhotoRequest(), handler));
        Assert.Equal(GnapErrorCode.UnknownInteraction, e.Code);
    }

    [Fact]
    public async Task ServerError_IsRetriedWithFreshSignatures()
    {
        using var h = ClientHarness.Create();
        h.As.Intercept(_ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        h.As.Intercept(_ => new HttpResponseMessage(HttpStatusCode.BadGateway));

        var result = await h.Client.RequestAccessAsync([AccessRight.ForReference("photo-api")]);

        Assert.NotNull(result.AccessToken);
        Assert.Equal(3, h.As.Requests.Count);
        Assert.Equal([TimeSpan.FromMilliseconds(500), TimeSpan.FromSeconds(1)], h.Time.Delays);
        // The AS requires unique nonces: the successful attempt carried a new signature.
        h.AssertAllRequestsVerified();
    }

    [Fact]
    public async Task ServerError_HonoursRetryAfter()
    {
        using var h = ClientHarness.Create();
        h.As.Intercept(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
            response.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromSeconds(4));
            return response;
        });

        await h.Client.RequestAccessAsync([AccessRight.ForReference("photo-api")]);

        Assert.Equal([TimeSpan.FromSeconds(4)], h.Time.Delays);
    }

    [Fact]
    public async Task ServerError_ExhaustedRetries_Throws()
    {
        using var h = ClientHarness.Create(o => o.MaxRetries = 2);
        for (var i = 0; i < 3; i++)
        {
            h.As.Intercept(_ => new HttpResponseMessage(HttpStatusCode.InternalServerError));
        }

        var e = await Assert.ThrowsAsync<GnapClientException>(
            () => h.Client.RequestAccessAsync([AccessRight.ForReference("photo-api")]));

        Assert.IsNotType<GnapProtocolException>(e);
        Assert.Equal(HttpStatusCode.InternalServerError, e.StatusCode);
        Assert.Equal(3, h.As.Requests.Count);
    }

    [Fact]
    public async Task TransportFailure_IsRetried()
    {
        using var h = ClientHarness.Create();
        h.As.Intercept(_ => throw new HttpRequestException("connection reset"));

        var result = await h.Client.RequestAccessAsync([AccessRight.ForReference("photo-api")]);

        Assert.NotNull(result.AccessToken);
    }

    [Fact]
    public async Task ClientError_WithoutGnapBody_IsNotSilent()
    {
        using var h = ClientHarness.Create();
        h.As.Intercept(_ => new HttpResponseMessage(HttpStatusCode.Forbidden)
        {
            Content = new StringContent("<html>nope</html>", Encoding.UTF8, "text/html"),
        });

        var e = await Assert.ThrowsAsync<GnapClientException>(
            () => h.Client.RequestAccessAsync([AccessRight.ForReference("photo-api")]));
        Assert.Equal(HttpStatusCode.Forbidden, e.StatusCode);
    }

    [Fact]
    public async Task MalformedSuccessBody_IsNotSilent()
    {
        using var h = ClientHarness.Create();
        h.As.Intercept(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{ not json") });

        await Assert.ThrowsAsync<GnapClientException>(
            () => h.Client.RequestAccessAsync([AccessRight.ForReference("photo-api")]));
    }

    [Fact]
    public async Task MissingConfiguration_Throws()
    {
        using var h = ClientHarness.Create(o => o.GrantEndpoint = null);
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => h.Client.RequestAccessAsync([AccessRight.ForReference("photo-api")]));
    }

    [Fact]
    public async Task UnsupportedHashMethod_IsRejectedBeforeSending()
    {
        using var h = ClientHarness.Create(o => o.FinishHashMethod = "md5");
        var handler = GnapInteractionHandler.Redirect(new Uri("https://client.example/cb"), (_, _) => throw new InvalidOperationException());

        await Assert.ThrowsAsync<GnapClientException>(
            () => h.Client.RequestAccessAsync(ClientHarness.PhotoRequest(), handler));
        Assert.Empty(h.As.Requests);
    }
}
