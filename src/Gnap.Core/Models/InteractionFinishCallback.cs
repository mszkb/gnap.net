using System.Text;
using System.Text.Json.Serialization;

namespace Gnap.Core.Models;

/// <summary>
/// The message the AS sends to the client instance when interaction has finished
/// (RFC 9635 Section 4.2): the interaction finish <see cref="Hash"/> and the
/// one-time <see cref="InteractRef"/>. For the <c>redirect</c> finish method both
/// values travel as query parameters of the callback URI (Section 4.2.1); for the
/// <c>push</c> method they form the JSON body of an HTTP POST (Section 4.2.2).
/// </summary>
public sealed class InteractionFinishCallback
{
    /// <summary>The query parameter / JSON member name of the finish hash.</summary>
    public const string HashParameter = "hash";

    /// <summary>The query parameter / JSON member name of the interaction reference.</summary>
    public const string InteractRefParameter = "interact_ref";

    /// <summary>The interaction finish hash (Section 4.2.3). Required.</summary>
    [JsonPropertyName(HashParameter)]
    public string? Hash { get; set; }

    /// <summary>The one-time interaction reference to send in the continuation request. Required.</summary>
    [JsonPropertyName(InteractRefParameter)]
    public string? InteractRef { get; set; }

    /// <summary>
    /// Builds the <c>redirect</c> finish URI (Section 4.2.1): the client's callback
    /// URI with <c>hash</c> and <c>interact_ref</c> appended as query parameters,
    /// keeping any query the client already put into its callback URI.
    /// </summary>
    /// <exception cref="GnapException">A required value is missing or the callback URI is not absolute.</exception>
    public Uri ToRedirectUri(string callbackUri)
    {
        ArgumentNullException.ThrowIfNull(callbackUri);
        RequireComplete();
        // On Unix "/path" parses as an absolute file: URI; a callback is never a local file.
        if (!Uri.TryCreate(callbackUri, UriKind.Absolute, out var uri) || uri.IsFile)
        {
            throw new GnapException("The interaction finish callback URI must be an absolute URI.");
        }

        var builder = new UriBuilder(uri);
        var query = new StringBuilder(builder.Query.TrimStart('?'));
        if (query.Length > 0)
        {
            query.Append('&');
        }

        query.Append(HashParameter).Append('=').Append(Uri.EscapeDataString(Hash!))
            .Append('&').Append(InteractRefParameter).Append('=').Append(Uri.EscapeDataString(InteractRef!));
        builder.Query = query.ToString();
        return builder.Uri;
    }

    /// <summary>
    /// Reads the <c>hash</c> and <c>interact_ref</c> query parameters of a
    /// <c>redirect</c> finish request (Section 4.2.1). Returns <see langword="false"/>
    /// when either parameter is missing, empty or repeated.
    /// </summary>
    public static bool TryParseRedirectUri(Uri redirectUri, out InteractionFinishCallback callback)
    {
        ArgumentNullException.ThrowIfNull(redirectUri);
        callback = new InteractionFinishCallback();
        if (!redirectUri.IsAbsoluteUri)
        {
            return false;
        }

        var query = redirectUri.Query.TrimStart('?');
        foreach (var pair in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = pair.IndexOf('=', StringComparison.Ordinal);
            var name = Unescape(separator < 0 ? pair : pair[..separator]);
            var value = separator < 0 ? string.Empty : Unescape(pair[(separator + 1)..]);
            switch (name)
            {
                case HashParameter when callback.Hash is null:
                    callback.Hash = value;
                    break;
                case InteractRefParameter when callback.InteractRef is null:
                    callback.InteractRef = value;
                    break;
                case HashParameter or InteractRefParameter:
                    // A repeated parameter is ambiguous; refuse rather than guess.
                    return false;
            }
        }

        return !string.IsNullOrEmpty(callback.Hash) && !string.IsNullOrEmpty(callback.InteractRef);
    }

    /// <summary>
    /// Verifies <see cref="Hash"/> against the locally known nonces and grant
    /// endpoint (Section 4.2.3), in constant time.
    /// </summary>
    /// <param name="clientNonce">The <c>nonce</c> the client sent in <c>interact.finish</c>.</param>
    /// <param name="asNonce">The <c>finish</c> nonce the AS returned in the <c>interact</c> response.</param>
    /// <param name="grantEndpointUri">The grant endpoint URI the client sent its initial request to.</param>
    /// <param name="hashMethod">The requested <c>hash_method</c>; <see langword="null"/> for <c>sha-256</c>.</param>
    public bool VerifyHash(string clientNonce, string asNonce, string grantEndpointUri, string? hashMethod = null) =>
        Hash is not null
        && InteractRef is not null
        && InteractionFinishHash.Verify(Hash, clientNonce, asNonce, InteractRef, grantEndpointUri, hashMethod);

    private void RequireComplete()
    {
        if (string.IsNullOrEmpty(Hash) || string.IsNullOrEmpty(InteractRef))
        {
            throw new GnapException("An interaction finish callback requires both 'hash' and 'interact_ref'.");
        }
    }

    private static string Unescape(string value) => Uri.UnescapeDataString(value.Replace('+', ' '));
}
