using System.Text;
using System.Text.Json;
using Gnap.AspNetCore.AuthorizationServer.Stores;
using Gnap.Core.Json;
using Gnap.Core.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Gnap.AspNetCore.AuthorizationServer.Endpoints;

/// <summary>
/// Resource set registration (RFC 9767 Section 3.4) at <c>POST {BasePath}/resource</c>.
/// A registered RS (identified by reference in <c>resource_server</c>, request signed
/// with its key) posts a list of rights of access and receives a
/// <c>resource_reference</c> that clients can request in place of the list.
/// </summary>
internal sealed class ResourceRegistrationEndpoint(
    IResourceServerStore resourceServers,
    IResourceSetStore resourceSets,
    KeyProofVerifier proofVerifier,
    IOptions<GnapAuthorizationServerOptions> options,
    ILogger<ResourceRegistrationEndpoint> logger)
{
    private readonly GnapAuthorizationServerOptions _options = options.Value;

    public async Task HandleAsync(HttpContext context)
    {
        var body = await Protocol.ReadBodyAsync(context, _options.MaxRequestBodySize).ConfigureAwait(false);
        if (body is null || !TryParse(body, out var resourceServerId, out var access))
        {
            await Protocol.WriteErrorAsync(context, GnapErrorCode.InvalidRequest).ConfigureAwait(false);
            return;
        }

        var resourceServer = await resourceServers.FindAsync(resourceServerId, context.RequestAborted).ConfigureAwait(false);
        if (resourceServer is null
            || !await proofVerifier.VerifyAsync(context, body, resourceServer.Key, "resource registration").ConfigureAwait(false))
        {
            logger.LogWarning("Rejected resource registration: unknown or unauthenticated resource server.");
            await Protocol.WriteErrorAsync(context, GnapErrorCode.InvalidClient).ConfigureAwait(false);
            return;
        }

        var registration = new ResourceSetRegistration
        {
            Reference = Protocol.NewSecret(16),
            ResourceServerId = resourceServer.Id,
            Access = access,
            RegisteredAt = _options.TimeProvider.GetUtcNow(),
        };
        await resourceSets.StoreAsync(registration, context.RequestAborted).ConfigureAwait(false);

        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("resource_reference", registration.Reference);
            writer.WriteEndObject();
        }

        await Protocol.WriteJsonAsync(context, StatusCodes.Status200OK, Encoding.UTF8.GetString(buffer.ToArray())).ConfigureAwait(false);
    }

    private static bool TryParse(byte[] body, out string resourceServerId, out IList<AccessRight> access)
    {
        resourceServerId = string.Empty;
        access = [];
        try
        {
            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty("resource_server", out var rs) || rs.ValueKind != JsonValueKind.String
                || !root.TryGetProperty("access", out var accessElement) || accessElement.ValueKind != JsonValueKind.Array)
            {
                return false;
            }

            resourceServerId = rs.GetString()!;
            access = accessElement.Deserialize(GnapJsonContext.Default.IListAccessRight) ?? [];
            return resourceServerId.Length > 0 && access.Count > 0;
        }
        catch (JsonException)
        {
            return false;
        }
    }
}
