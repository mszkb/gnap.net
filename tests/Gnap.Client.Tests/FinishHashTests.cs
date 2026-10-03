using Gnap.Client.Interaction;
using Gnap.Client.Tests.Infrastructure;
using Gnap.Core.Json;
using Gnap.Core.Models;
using Xunit;

namespace Gnap.Client.Tests;

/// <summary>Finish-hash verification of the redirect and push callbacks (RFC 9635 Section 4.2.3).</summary>
public class FinishHashTests
{
    private static async Task<(ClientHarness Harness, GnapPendingGrant Pending)> StartAsync(string finishMethod = FinishMethods.Redirect)
    {
        var h = ClientHarness.Create();
        var pending = await h.Client.StartGrantAsync(ClientHarness.PhotoRequest(new InteractRequest
        {
            Start = [new StartMode(StartModes.Redirect)],
            Finish = new InteractFinish { Method = finishMethod, Uri = "https://client.example/cb" },
        }));
        return (h, pending);
    }

    [Fact]
    public async Task ValidHash_IsAccepted()
    {
        var (h, pending) = await StartAsync();
        using (h)
        {
            var result = await pending.CompleteWithRedirectAsync(h.As.ApproveAndRedirect());
            Assert.NotNull(result.AccessToken);
        }
    }

    [Fact]
    public async Task TamperedHash_IsRejectedWithoutContinuing()
    {
        var (h, pending) = await StartAsync();
        using (h)
        {
            await Assert.ThrowsAsync<GnapInteractionException>(
                () => pending.CompleteWithRedirectAsync(h.As.ApproveAndRedirect(tamperHash: true)));
            Assert.DoesNotContain(h.As.Requests, r => r.Path.StartsWith("/continue/", StringComparison.Ordinal));
        }
    }

    [Fact]
    public async Task TamperedInteractRef_IsRejected()
    {
        var (h, pending) = await StartAsync();
        using (h)
        {
            var callback = h.As.Approve();
            callback.InteractRef = "attacker-ref";
            await Assert.ThrowsAsync<GnapInteractionException>(
                () => pending.CompleteAsync(GnapInteractionOutcome.FromCallback(callback)));
        }
    }

    [Fact]
    public async Task MissingHash_IsRejected()
    {
        var (h, pending) = await StartAsync();
        using (h)
        {
            var callback = h.As.Approve();
            var uri = new Uri($"https://client.example/cb?interact_ref={callback.InteractRef}");
            await Assert.ThrowsAsync<GnapInteractionException>(() => pending.CompleteWithRedirectAsync(uri));
            await Assert.ThrowsAsync<GnapInteractionException>(
                () => pending.CompleteAsync(GnapInteractionOutcome.FromCallback(new InteractionFinishCallback { InteractRef = callback.InteractRef })));
            Assert.DoesNotContain(h.As.Requests, r => r.Path.StartsWith("/continue/", StringComparison.Ordinal));
        }
    }

    [Fact]
    public async Task RepeatedParameter_IsRejected()
    {
        var (h, pending) = await StartAsync();
        using (h)
        {
            var redirect = h.As.ApproveAndRedirect();
            var doubled = new Uri(redirect.AbsoluteUri + "&hash=other");
            await Assert.ThrowsAsync<GnapInteractionException>(() => pending.CompleteWithRedirectAsync(doubled));
        }
    }

    [Fact]
    public async Task ReplayedCallback_IsRejected()
    {
        var (h, pending) = await StartAsync();
        using (h)
        {
            var redirect = h.As.ApproveAndRedirect();
            await pending.CompleteWithRedirectAsync(redirect);
            await Assert.ThrowsAsync<GnapInteractionException>(() => pending.CompleteWithRedirectAsync(redirect));
        }
    }

    [Fact]
    public async Task MissingAsFinishNonce_IsRejected()
    {
        using var h = ClientHarness.Create();
        h.As.OmitFinishNonce = true;
        var pending = await h.Client.StartGrantAsync(ClientHarness.PhotoRequest(new InteractRequest
        {
            Start = [new StartMode(StartModes.Redirect)],
            Finish = new InteractFinish { Method = FinishMethods.Redirect, Uri = "https://client.example/cb" },
        }));

        await Assert.ThrowsAsync<GnapInteractionException>(
            () => pending.CompleteWithRedirectAsync(h.As.ApproveAndRedirect()));
    }

    [Fact]
    public async Task Push_TamperedHash_IsRejected()
    {
        var (h, pending) = await StartAsync(FinishMethods.Push);
        using (h)
        {
            var body = GnapJson.Serialize(h.As.Approve(tamperHash: true));
            await Assert.ThrowsAsync<GnapInteractionException>(() => pending.CompleteWithPushAsync(body));
        }
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{\"interact_ref\":\"x\"}")]
    [InlineData("not json")]
    public async Task Push_MissingHashOrMalformed_IsRejected(string body)
    {
        var (h, pending) = await StartAsync(FinishMethods.Push);
        using (h)
        {
            await Assert.ThrowsAsync<GnapInteractionException>(() => pending.CompleteWithPushAsync(body));
        }
    }

    [Fact]
    public async Task CallbackWithoutRequestedFinish_IsRejected()
    {
        using var h = ClientHarness.Create();
        var pending = await h.Client.StartGrantAsync(ClientHarness.PhotoRequest(new InteractRequest
        {
            Start = [new StartMode(StartModes.UserCode)],
        }));
        var forged = new InteractionFinishCallback { Hash = "abc", InteractRef = "def" };

        await Assert.ThrowsAsync<GnapInteractionException>(
            () => pending.CompleteAsync(GnapInteractionOutcome.FromCallback(forged)));
    }
}
