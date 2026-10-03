using Gnap.Client.Tokens;
using Gnap.Core.Models;

namespace Gnap.Client;

/// <summary>The outcome of a completed grant: the issued tokens and subject information.</summary>
public sealed class GnapGrantResult
{
    internal GnapGrantResult(GrantResponse response, IReadOnlyList<GnapAccessToken> accessTokens)
    {
        Response = response;
        AccessTokens = accessTokens;
    }

    /// <summary>The final grant response.</summary>
    public GrantResponse Response { get; }

    /// <summary>The issued access tokens (empty when only subject information was requested).</summary>
    public IReadOnlyList<GnapAccessToken> AccessTokens { get; }

    /// <summary>The single (or first) issued access token, if any.</summary>
    public GnapAccessToken? AccessToken => AccessTokens.Count > 0 ? AccessTokens[0] : null;

    /// <summary>The released subject information, if any.</summary>
    public SubjectResponse? Subject => Response.Subject;

    /// <summary>The instance identifier the AS assigned to this client instance, if any.</summary>
    public string? InstanceId => Response.InstanceId;

    /// <summary>The continuation information for later grant modification or revocation, if offered.</summary>
    public ContinueResponse? Continue => Response.Continue;

    /// <summary>Returns the token issued for the given label (multiple-token requests, RFC 9635 Section 2.1.2).</summary>
    /// <exception cref="KeyNotFoundException">No token carries this label.</exception>
    public GnapAccessToken GetToken(string label) =>
        AccessTokens.FirstOrDefault(t => t.Label == label)
        ?? throw new KeyNotFoundException($"No access token with label '{label}' was issued.");
}
