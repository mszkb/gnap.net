using System.Net;
using System.Text;
using System.Text.Json;
using System.Web;
using Gnap.Client;
using Gnap.Core.Keys;
using Gnap.Core.Models;

namespace Gnap.Interop.Tests.Rafiki;

/// <summary>
/// Gnap.Client against the Rafiki auth server (Interledger, the Open Payments GNAP
/// AS). Requires a running Rafiki auth service; see <c>interop/rafiki</c>.
/// <list type="bullet">
/// <item><c>GNAP_INTEROP_RAFIKI</c> — enables the tests (any value).</item>
/// <item><c>RAFIKI_AUTH_URL</c>, <c>RAFIKI_INTERACTION_URL</c>, <c>RAFIKI_INTROSPECTION_URL</c> — the three Rafiki auth ports.</item>
/// <item><c>RAFIKI_TENANT_ID</c>, <c>RAFIKI_IDP_SECRET</c> — the operator tenant and its identity provider secret.</item>
/// <item><c>INTEROP_WALLET_PORT</c>, <c>INTEROP_WALLET_BASE</c> — where the test's wallet address server listens, and the base URI Rafiki uses to reach it.</item>
/// </list>
/// </summary>
public sealed class RafikiInteropTests : IAsyncLifetime
{
    private const string Enable = "GNAP_INTEROP_RAFIKI";

    private static readonly Uri AuthUrl = new(InteropEnvironment.Get("RAFIKI_AUTH_URL", "http://localhost:3006"));
    private static readonly Uri InteractionUrl = new(InteropEnvironment.Get("RAFIKI_INTERACTION_URL", "http://localhost:3009"));
    private static readonly Uri IntrospectionUrl = new(InteropEnvironment.Get("RAFIKI_INTROSPECTION_URL", "http://localhost:3007"));
    private static readonly string TenantId = InteropEnvironment.Get("RAFIKI_TENANT_ID", "438fa74a-fa7d-4317-9ced-dde32ece1787");
    private static readonly string IdpSecret = InteropEnvironment.Get("RAFIKI_IDP_SECRET", "interop-idp-secret");
    private static readonly int WalletPort = int.Parse(InteropEnvironment.Get("INTEROP_WALLET_PORT", "5199"), System.Globalization.CultureInfo.InvariantCulture);
    private static readonly Uri WalletBase = new(InteropEnvironment.Get("INTEROP_WALLET_BASE", $"http://localhost:{WalletPort}/"));

    private readonly JsonWebKey _key = TestKeys.NewEd25519("interop-" + Guid.NewGuid().ToString("N")[..8]);
    private WalletAddressServer? _wallet;

    private static Uri GrantEndpoint => new(AuthUrl, TenantId);

    public async Task InitializeAsync()
    {
        if (Environment.GetEnvironmentVariable(Enable) is { Length: > 0 })
        {
            _wallet = await WalletAddressServer.StartAsync(WalletPort, WalletBase, AuthUrl, _key);
        }
    }

    public async Task DisposeAsync()
    {
        if (_wallet is not null)
        {
            await _wallet.DisposeAsync();
        }
    }

    [InteropFact(Enable)]
    public async Task Discovery_endpoint_is_reachable()
    {
        using var http = new HttpClient();
        var discovery = await http.GetStringAsync(new Uri(AuthUrl, "discovery"));
        using var document = JsonDocument.Parse(discovery);
        Assert.Contains(
            "redirect",
            document.RootElement.GetProperty("interaction_start_modes_supported").EnumerateArray().Select(e => e.GetString()));
    }

    [InteropFact(Enable)]
    public async Task Non_interactive_grant_issues_a_token_that_Rafiki_introspects_rotates_and_revokes()
    {
        var walletAddress = _wallet!.WalletAddress("alice");
        var client = CreateClient(walletAddress);

        var result = await client.RequestAccessAsync(new GrantRequest
        {
            AccessToken =
            [
                new AccessTokenRequest
                {
                    Access = [new AccessRight { Type = "incoming-payment", Actions = ["create", "read"], Identifier = walletAddress }],
                },
            ],
        });

        var token = Assert.IsType<Gnap.Client.Tokens.GnapAccessToken>(result.AccessToken);
        Assert.True(token.CanBeManaged);
        Assert.True(await IntrospectAsync(token.Value));

        // Token rotation (RFC 9635 Section 6.1) — signed with the management token.
        var rotated = await client.RotateTokenAsync(token);
        Assert.NotEqual(token.Value, rotated.Value);
        Assert.True(await IntrospectAsync(rotated.Value));
        Assert.False(await IntrospectAsync(token.Value));

        // Token revocation (RFC 9635 Section 6.2).
        await client.RevokeTokenAsync(rotated);
        Assert.False(await IntrospectAsync(rotated.Value));
    }

    [InteropFact(Enable)]
    public async Task Interactive_grant_completes_through_redirect_finish_and_continuation()
    {
        var walletAddress = _wallet!.WalletAddress("alice");
        var client = CreateClient(walletAddress);
        var callback = new Uri(WalletBase, "callback?state=interop&x=a+b");

        var pending = await client.StartGrantAsync(new GrantRequest
        {
            AccessToken =
            [
                new AccessTokenRequest
                {
                    Access =
                    [
                        new AccessRight { Type = "outgoing-payment", Actions = ["create", "read"], Identifier = walletAddress },
                    ],
                },
            ],
            Interact = new InteractRequest
            {
                Start = [new StartMode(StartModes.Redirect)],
                Finish = new InteractFinish { Method = FinishMethods.Redirect, Uri = callback.AbsoluteUri },
            },
        });

        Assert.False(pending.IsCompleted);
        var redirect = Assert.IsType<Uri>(pending.Interaction?.RedirectUri);

        // The user's browser: start the interaction, which sends it to the tenant's
        // identity provider; the IdP accepts the grant on Rafiki's interaction API and
        // returns the browser to Rafiki's finish endpoint, which redirects to the client.
        using var browser = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false, CookieContainer = new CookieContainer() });
        using var start = await browser.GetAsync(redirect);
        Assert.Equal(HttpStatusCode.Redirect, start.StatusCode);
        var idp = HttpUtility.ParseQueryString(start.Headers.Location!.Query);
        var interactId = idp["interactId"]!;
        var nonce = idp["nonce"]!;

        using (var accept = new HttpRequestMessage(HttpMethod.Post, new Uri(InteractionUrl, $"grant/{interactId}/{nonce}/accept")))
        {
            accept.Headers.Add("x-idp-secret", IdpSecret);
            accept.Content = new StringContent("{}", Encoding.UTF8, "application/json");
            using var accepted = await browser.SendAsync(accept);
            Assert.True(accepted.IsSuccessStatusCode, $"accept: {(int)accepted.StatusCode} {await accepted.Content.ReadAsStringAsync()}");
        }

        using var finish = await browser.GetAsync(new Uri(AuthUrl, $"interact/{interactId}/{nonce}/finish"));
        Assert.Equal(HttpStatusCode.Redirect, finish.StatusCode);
        var finishRedirect = finish.Headers.Location!;
        Assert.StartsWith(new Uri(WalletBase, "callback").AbsoluteUri, finishRedirect.AbsoluteUri, StringComparison.Ordinal);

        // Verifies the interaction hash and continues the grant with interact_ref.
        var result = await pending.CompleteWithRedirectAsync(finishRedirect);
        var token = Assert.IsType<Gnap.Client.Tokens.GnapAccessToken>(result.AccessToken);
        Assert.Equal("outgoing-payment", Assert.Single(token.Access!).Type);
        Assert.True(await IntrospectAsync(token.Value));

        await client.RevokeTokenAsync(token);
        Assert.False(await IntrospectAsync(token.Value));
    }

    [InteropFact(Enable)]
    public async Task Rafiki_rejects_a_request_signed_with_a_key_the_wallet_does_not_publish()
    {
        var walletAddress = _wallet!.WalletAddress("alice");
        var client = new GnapClient(new HttpClient(), new GnapClientOptions
        {
            GrantEndpoint = GrantEndpoint,
            ClientKey = GnapClientKey.FromJwk(TestKeys.NewEd25519(_key.Kid!)), // same kid, other key
            InstanceId = walletAddress,
            MaxRetries = 0,
        });

        var error = await Assert.ThrowsAsync<GnapProtocolException>(() => client.RequestAccessAsync(new GrantRequest
        {
            AccessToken = [new AccessTokenRequest { Access = [new AccessRight { Type = "incoming-payment", Actions = ["read"], Identifier = walletAddress }] }],
        }));
        Assert.Equal(GnapErrorCode.InvalidClient, error.Code);
    }

    private GnapClient CreateClient(string walletAddress) =>
        new(new HttpClient(), new GnapClientOptions
        {
            GrantEndpoint = GrantEndpoint,
            ClientKey = GnapClientKey.FromJwk(_key),
            // Open Payments identifies client instances by their wallet address.
            InstanceId = walletAddress,
            MaxRetries = 0,
        });

    private static async Task<bool> IntrospectAsync(string token)
    {
        using var http = new HttpClient();
        using var response = await http.PostAsync(
            IntrospectionUrl,
            new StringContent(JsonSerializer.Serialize(new Dictionary<string, string> { ["access_token"] = token }), Encoding.UTF8, "application/json"));
        var body = await response.Content.ReadAsStringAsync();
        Assert.True(response.IsSuccessStatusCode, $"introspection: {(int)response.StatusCode} {body}");
        using var document = JsonDocument.Parse(body);
        return document.RootElement.GetProperty("active").GetBoolean();
    }
}
