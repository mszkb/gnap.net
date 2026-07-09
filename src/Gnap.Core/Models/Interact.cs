using System.Text.Json;
using System.Text.Json.Serialization;
using Gnap.Core.Json;

namespace Gnap.Core.Models;

/// <summary>The registered interaction start mode names of RFC 9635.</summary>
public static class StartModes
{
    /// <summary>Redirect the end user to an arbitrary URI.</summary>
    public const string Redirect = "redirect";

    /// <summary>Launch an application URI on the end user's device.</summary>
    public const string App = "app";

    /// <summary>Display a short user code for entry at a stable URI.</summary>
    public const string UserCode = "user_code";

    /// <summary>Display a short user code together with a short dynamic URI.</summary>
    public const string UserCodeUri = "user_code_uri";
}

/// <summary>The registered interaction finish method names of RFC 9635.</summary>
public static class FinishMethods
{
    /// <summary>The client receives a redirect through the end user's browser.</summary>
    public const string Redirect = "redirect";

    /// <summary>The client receives a direct HTTP POST from the AS.</summary>
    public const string Push = "push";
}

/// <summary>
/// One element of the interaction <c>start</c> array: either a bare mode name
/// string or an object with a <c>mode</c> member plus extension parameters.
/// </summary>
[JsonConverter(typeof(StartModeConverter))]
public sealed class StartMode
{
    /// <summary>Creates a start mode.</summary>
    public StartMode(string mode)
    {
        ArgumentException.ThrowIfNullOrEmpty(mode);
        Mode = mode;
    }

    /// <summary>The start mode name, e.g. <see cref="StartModes.Redirect"/>.</summary>
    public string Mode { get; }

    /// <summary>Mode-specific parameters when the mode was sent in object form.</summary>
    public IDictionary<string, JsonElement>? Parameters { get; set; }
}

/// <summary>The <c>interact</c> field of a grant request (RFC 9635 Section 2.5).</summary>
public sealed class InteractRequest
{
    /// <summary>How the client instance can start interaction. Required.</summary>
    [JsonPropertyName("start")]
    public IList<StartMode>? Start { get; set; }

    /// <summary>How the client instance can learn that interaction has finished.</summary>
    [JsonPropertyName("finish")]
    public InteractFinish? Finish { get; set; }

    /// <summary>Hints to inform the interaction process.</summary>
    [JsonPropertyName("hints")]
    public InteractHints? Hints { get; set; }
}

/// <summary>The interaction <c>finish</c> object of a grant request (RFC 9635 Section 2.5.2).</summary>
public sealed class InteractFinish
{
    /// <summary>The callback method, e.g. <see cref="FinishMethods.Redirect"/>. Required.</summary>
    [JsonPropertyName("method")]
    public string? Method { get; set; }

    /// <summary>The absolute callback URI without fragment. Required for <c>redirect</c> and <c>push</c>.</summary>
    [JsonPropertyName("uri")]
    public string? Uri { get; set; }

    /// <summary>The client's unique, unguessable nonce for the finish hash. Required.</summary>
    [JsonPropertyName("nonce")]
    public string? Nonce { get; set; }

    /// <summary>The hash method for the finish hash; <c>sha-256</c> when absent.</summary>
    [JsonPropertyName("hash_method")]
    public string? HashMethod { get; set; }
}

/// <summary>The interaction <c>hints</c> object of a grant request (RFC 9635 Section 2.5.3).</summary>
public sealed class InteractHints
{
    /// <summary>The end user's preferred locales (RFC 5646 tags).</summary>
    [JsonPropertyName("ui_locales")]
    public IList<string>? UiLocales { get; set; }

    /// <summary>Extension hints from the GNAP Interaction Hints registry.</summary>
    [JsonExtensionData]
    public IDictionary<string, JsonElement>? AdditionalFields { get; set; }
}

/// <summary>The <c>interact</c> field of a grant response (RFC 9635 Section 3.3).</summary>
public sealed class InteractResponse
{
    /// <summary>The URI to direct the end user to (<c>redirect</c> start mode).</summary>
    [JsonPropertyName("redirect")]
    public string? Redirect { get; set; }

    /// <summary>The application URI to launch (<c>app</c> start mode).</summary>
    [JsonPropertyName("app")]
    public string? App { get; set; }

    /// <summary>The short code to display (<c>user_code</c> start mode).</summary>
    [JsonPropertyName("user_code")]
    public string? UserCode { get; set; }

    /// <summary>The short code and URI to display (<c>user_code_uri</c> start mode).</summary>
    [JsonPropertyName("user_code_uri")]
    public UserCodeUri? UserCodeUri { get; set; }

    /// <summary>The AS nonce for validating the interaction finish callback.</summary>
    [JsonPropertyName("finish")]
    public string? Finish { get; set; }

    /// <summary>Seconds after which these interaction responses expire.</summary>
    [JsonPropertyName("expires_in")]
    public long? ExpiresIn { get; set; }

    /// <summary>Extension fields from the GNAP Interaction Mode Responses registry.</summary>
    [JsonExtensionData]
    public IDictionary<string, JsonElement>? AdditionalFields { get; set; }
}

/// <summary>The <c>user_code_uri</c> interaction response object.</summary>
public sealed class UserCodeUri
{
    /// <summary>The short code the end user types in. Required.</summary>
    [JsonPropertyName("code")]
    public string? Code { get; set; }

    /// <summary>The short absolute URI the end user visits. Required.</summary>
    [JsonPropertyName("uri")]
    public string? Uri { get; set; }
}
