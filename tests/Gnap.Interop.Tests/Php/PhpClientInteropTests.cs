using System.Diagnostics;
using System.Text.Json;
using Gnap.AspNetCore.AuthorizationServer;
using Gnap.AspNetCore.AuthorizationServer.Interaction;
using Gnap.AspNetCore.AuthorizationServer.Policy;
using Gnap.Core.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Gnap.Interop.Tests.Php;

/// <summary>
/// aaronpk/gnap-client-php (an independent PHP client) against the Gnap.AspNetCore
/// authorization server on a real Kestrel port: the full redirect flow of
/// <c>interop/php-client/driver.php</c>.
/// <list type="bullet">
/// <item><c>GNAP_INTEROP_PHP_CLIENT</c> — path of a gnap-client-php checkout with
/// <c>composer install</c> done and <c>interop/php-client/rfc9635-signatures.patch</c>
/// applied (see <c>interop/php-client/setup.sh</c>).</item>
/// <item><c>GNAP_INTEROP_PHP</c> — the PHP binary (default <c>php</c>).</item>
/// <item><c>INTEROP_AS_PORT</c> — the AS port (default 5299).</item>
/// </list>
/// </summary>
public sealed class PhpClientInteropTests
{
    private const string Enable = "GNAP_INTEROP_PHP_CLIENT";

    [InteropFact(Enable)]
    public Task Redirect_flow_with_sha3_512_finish_hash() => RunFlowAsync("sha3-512");

    [InteropFact(Enable)]
    public Task Redirect_flow_with_default_sha_256_finish_hash() => RunFlowAsync("sha-256");

    private static async Task RunFlowAsync(string hashMethod)
    {
        var port = int.Parse(InteropEnvironment.Get("INTEROP_AS_PORT", "5299"), System.Globalization.CultureInfo.InvariantCulture);
        var origin = new Uri($"http://localhost:{port}/");
        await using var app = await StartAuthorizationServerAsync(origin);

        var (exitCode, output) = await RunPhpAsync(
            Path.Combine(InteropEnvironment.RepositoryRoot, "interop", "php-client", "driver.php"),
            Environment.GetEnvironmentVariable(Enable)!,
            new Uri(origin, "gnap/tx").AbsoluteUri,
            new Uri(origin, "php-client/callback?session=1").AbsoluteUri,
            hashMethod);

        Assert.True(exitCode == 0, $"driver.php exited with {exitCode}:\n{output}");
        using var report = JsonDocument.Parse(output);
        var root = report.RootElement;
        Assert.Equal("ok", root.GetProperty("result").GetString());
        Assert.True(root.GetProperty("hash_valid").GetBoolean());
        var continued = root.GetProperty("continue_response");
        Assert.False(string.IsNullOrEmpty(continued.GetProperty("access_token").GetProperty("value").GetString()));
        Assert.Equal("interop-user", continued.GetProperty("subject").GetProperty("sub_ids")[0].GetProperty("id").GetString());
    }

    private static async Task<WebApplication> StartAuthorizationServerAsync(Uri origin)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls($"http://0.0.0.0:{origin.Port}");
        builder.Services
            .AddGnapAuthorizationServer(options =>
            {
                options.PublicOrigin = origin;
                options.SubjectIdFormatsSupported = [SubjectIdentifierFormats.Opaque];
                // gnap-client-php sends no signature nonce (RFC 9635: SHOULD, not MUST).
                options.RequireSignatureNonce = false;
            })
            .AddGrantPolicy(_ => GrantDecision.RequireInteraction());

        var app = builder.Build();
        app.MapGnapAuthorizationServer();

        // The simulated resource owner approves every interaction.
        app.MapGet("/consent", async context =>
        {
            var interactions = context.RequestServices.GetRequiredService<IGnapInteractionService>();
            var id = context.Request.Query["interaction"].ToString();
            var completion = await interactions.ApproveAsync(context, id, new GrantApproval
            {
                ResourceOwner = "interop-user",
                Subject = new SubjectResponse
                {
                    SubIds = [new SubjectIdentifier { Format = SubjectIdentifierFormats.Opaque, Id = "interop-user" }],
                },
            });
            if (completion is { Succeeded: true, RedirectUri: { } redirect })
            {
                context.Response.Redirect(redirect.AbsoluteUri);
            }
            else
            {
                context.Response.StatusCode = StatusCodes.Status409Conflict;
            }
        });
        app.MapGet("/php-client/callback", () => Results.Text("callback received"));

        await app.StartAsync();
        return app;
    }

    private static async Task<(int ExitCode, string Output)> RunPhpAsync(params string[] arguments)
    {
        var start = new ProcessStartInfo(InteropEnvironment.Get("GNAP_INTEROP_PHP", "php"))
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await process.WaitForExitAsync(timeout.Token);
        return (process.ExitCode, await stdout + await stderr);
    }
}
