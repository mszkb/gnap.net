using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text.Json;
using Gnap.Core;
using Gnap.Core.Json;
using Gnap.Core.Keys;
using Gnap.Core.Models;
using Gnap.Core.Proofing;
using Gnap.HttpMessageSignatures.AspNetCore;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace GnapCore.Demo;

/// <summary>
/// A deliberately tiny, single-grant GNAP authorization server built from the
/// Phase 1 primitives alone. It validates httpsig key proofs, hands out an
/// interaction redirect, computes the finish hash and issues an access token on
/// continuation. It exists to exercise <c>Gnap.Core</c> end to end — the real,
/// pluggable AS framework arrives in Phase 3.
/// </summary>
internal sealed class MiniAuthorizationServer : IAsyncDisposable
{
    private readonly WebApplication _app;

    private MiniAuthorizationServer(WebApplication app, string baseUri)
    {
        _app = app;
        GrantEndpointUri = $"{baseUri}/gnap";
        InteractionFinishUri = $"{baseUri}/interact/finish";
    }

    /// <summary>The grant endpoint — also the AS identifier used in the finish hash.</summary>
    public string GrantEndpointUri { get; }

    /// <summary>Demo endpoint standing in for the RO approving and the AS calling back.</summary>
    public string InteractionFinishUri { get; }

    public static async Task<MiniAuthorizationServer> StartAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");

        var app = builder.Build();
        var state = new AsState();

        app.MapPost("/gnap", async (HttpContext context) =>
        {
            var body = await ReadBodyAsync(context.Request);
            var grantRequest = TryParse(body, GnapJsonContext.Default.GrantRequest);
            var jwk = grantRequest?.Client?.Key?.Jwk;
            if (jwk is null)
            {
                return Error(GnapErrorCode.InvalidClient, "The request carries no client key by value.");
            }

            var proof = await state.ProofValidator(jwk.Kid).ValidateAsync(new KeyProofContext
            {
                Message = new AspNetCoreRequestContext(context.Request),
                Key = jwk.ToSignatureAlgorithm(),
                Content = body,
            });
            if (!proof.Succeeded)
            {
                // Log the reason, answer generically: no oracle for attackers.
                Console.WriteLine($"    [mini-AS] proof rejected: {proof.FailureReason}");
                return Error(GnapErrorCode.InvalidClient, "Key proof validation failed.");
            }

            var clientNonce = grantRequest!.Interact?.Finish?.Nonce;
            if (clientNonce is null)
            {
                return Error(GnapErrorCode.InvalidInteraction, "This demo AS requires an interact.finish nonce.");
            }

            var grant = state.CreateGrant(jwk, clientNonce);
            return Results.Json(new GrantResponse
            {
                Interact = new InteractResponse
                {
                    Redirect = $"http://127.0.0.1/interact/{grant.Id}",
                    Finish = grant.AsNonce,
                },
                Continue = new ContinueResponse
                {
                    Uri = grant.ContinueUri,
                    Wait = 5,
                    AccessToken = new AccessTokenResponse { Value = grant.ContinuationToken },
                },
            }, GnapJsonContext.Default.GrantResponse);
        });

        // Demo shortcut: "the RO approved" — returns what the finish callback to
        // the client's URI would carry (interact_ref plus the finish hash).
        app.MapGet("/interact/finish", () =>
        {
            if (state.Grant is not { } grant)
            {
                return Results.NotFound();
            }

            var hash = InteractionFinishHash.Compute(
                grant.ClientNonce, grant.AsNonce, grant.InteractRef, state.GrantEndpointUri!);
            return Results.Json(new Dictionary<string, string>
            {
                ["interact_ref"] = grant.InteractRef,
                ["hash"] = hash,
            }, GnapJsonContext.Default.DictionaryStringString);
        });

        app.MapPost("/continue/{id}", async (HttpContext context, string id) =>
        {
            if (state.Grant is not { } grant || grant.Id != id)
            {
                return Error(GnapErrorCode.InvalidContinuation, "Unknown grant.");
            }

            // The continuation access token is bound to the client's key: the
            // Authorization header must be present, correct, and covered by a
            // fresh signature made with the key from the initial request.
            var authorization = context.Request.Headers.Authorization.ToString();
            if (authorization != $"GNAP {grant.ContinuationToken}")
            {
                return Error(GnapErrorCode.InvalidContinuation, "Missing or wrong continuation access token.");
            }

            var body = await ReadBodyAsync(context.Request);
            var proof = await state.ProofValidator(grant.ClientKey.Kid).ValidateAsync(new KeyProofContext
            {
                Message = new AspNetCoreRequestContext(context.Request),
                Key = grant.ClientKey.ToSignatureAlgorithm(),
                Content = body,
            });
            if (!proof.Succeeded)
            {
                Console.WriteLine($"    [mini-AS] continuation proof rejected: {proof.FailureReason}");
                return Error(GnapErrorCode.InvalidContinuation, "Key proof validation failed.");
            }

            var continueRequest = TryParse(body, GnapJsonContext.Default.ContinueRequest);
            if (continueRequest?.InteractRef != grant.InteractRef)
            {
                return Error(GnapErrorCode.InvalidInteraction, "Wrong interaction reference.");
            }

            state.Grant = null; // interact_ref is one-time-use
            return Results.Json(new GrantResponse
            {
                AccessToken = [new AccessTokenResponse
                {
                    Value = AsState.NewToken(),
                    Access = [AccessRight.ForReference("dolphin-metadata")],
                    ExpiresIn = 3600,
                }],
            }, GnapJsonContext.Default.GrantResponse);
        });

        await app.StartAsync();
        var baseUri = app.Urls.First().TrimEnd('/');
        state.GrantEndpointUri = $"{baseUri}/gnap";
        state.ContinueUriBase = $"{baseUri}/continue";
        return new MiniAuthorizationServer(app, baseUri);
    }

    public async ValueTask DisposeAsync() => await _app.DisposeAsync();

    private static IResult Error(GnapErrorCode code, string description) =>
        Results.Json(
            new GrantResponse { Error = new GnapError(code, description) },
            GnapJsonContext.Default.GrantResponse,
            statusCode: StatusCodes.Status400BadRequest);

    private static async Task<byte[]> ReadBodyAsync(HttpRequest request)
    {
        using var buffer = new MemoryStream();
        await request.Body.CopyToAsync(buffer);
        return buffer.ToArray();
    }

    private static T? TryParse<T>(byte[] body, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> typeInfo)
        where T : class
    {
        try
        {
            return JsonSerializer.Deserialize(body, typeInfo);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private sealed class AsState
    {
        private readonly InMemoryNonceStore _nonceStore = new();

        public string? GrantEndpointUri { get; set; }

        public string? ContinueUriBase { get; set; }

        public PendingGrant? Grant { get; set; }

        /// <summary>One shared nonce store across all endpoints: replays are replays everywhere.</summary>
        public HttpSigKeyProofValidator ProofValidator(string? expectedKeyId) => new()
        {
            NonceStore = _nonceStore,
            RequireNonce = true,
            ExpectedKeyId = expectedKeyId,
        };

        public PendingGrant CreateGrant(JsonWebKey clientKey, string clientNonce)
        {
            var grant = new PendingGrant(
                Id: NewToken(),
                ClientKey: clientKey,
                ClientNonce: clientNonce,
                AsNonce: NewToken(),
                InteractRef: NewToken(),
                ContinuationToken: NewToken(),
                ContinueUri: string.Empty);
            grant = grant with { ContinueUri = $"{ContinueUriBase}/{grant.Id}" };
            Grant = grant;
            return grant;
        }

        public static string NewToken() => Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(16));
    }

    private sealed record PendingGrant(
        string Id,
        JsonWebKey ClientKey,
        string ClientNonce,
        string AsNonce,
        string InteractRef,
        string ContinuationToken,
        string ContinueUri);
}
