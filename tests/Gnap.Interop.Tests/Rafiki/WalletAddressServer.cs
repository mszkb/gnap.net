using System.Text.Json;
using Gnap.Core.Json;
using Gnap.Core.Keys;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Gnap.Interop.Tests.Rafiki;

/// <summary>
/// The Open Payments side Rafiki's auth server needs from a client: a wallet address
/// (the GNAP client instance identifier, RFC 9635 Section 2.3) whose
/// <c>jwks.json</c> publishes the client's Ed25519 key. Rafiki resolves the
/// signature <c>keyid</c> against this key set.
/// </summary>
internal sealed class WalletAddressServer : IAsyncDisposable
{
    private readonly WebApplication _app;

    private WalletAddressServer(WebApplication app, Uri publicBase)
    {
        _app = app;
        PublicBase = publicBase;
    }

    /// <summary>The base URI under which Rafiki reaches this server.</summary>
    public Uri PublicBase { get; }

    /// <summary>The wallet address of the given account, as seen by Rafiki.</summary>
    public string WalletAddress(string account) => new Uri(PublicBase, account).AbsoluteUri;

    public static async Task<WalletAddressServer> StartAsync(int port, Uri publicBase, Uri authServer, JsonWebKey publicKey)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls($"http://0.0.0.0:{port}");
        var app = builder.Build();

        var jwk = JsonSerializer.Serialize(publicKey.ToPublicKey(), GnapJsonContext.Default.JsonWebKey);
        app.MapGet("/{account}", (string account) => Results.Text(
            $$"""
            {"id":"{{new Uri(publicBase, account).AbsoluteUri}}","publicName":"Interop {{account}}","assetCode":"USD","assetScale":2,"authServer":"{{authServer.AbsoluteUri.TrimEnd('/')}}","resourceServer":"{{publicBase.AbsoluteUri.TrimEnd('/')}}"}
            """,
            "application/json"));
        app.MapGet("/{account}/jwks.json", () => Results.Text($$"""{"keys":[{{jwk}}]}""", "application/json"));

        await app.StartAsync();
        return new WalletAddressServer(app, publicBase);
    }

    public async ValueTask DisposeAsync() => await _app.DisposeAsync();
}
