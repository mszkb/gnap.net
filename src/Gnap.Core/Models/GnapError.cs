using System.Text.Json.Serialization;
using Gnap.Core.Json;

namespace Gnap.Core.Models;

/// <summary>
/// An error code from the GNAP Error Codes registry (RFC 9635 Section 3.6),
/// modeled as an open string wrapper so extension codes round-trip.
/// </summary>
[JsonConverter(typeof(GnapErrorCodeConverter))]
public readonly record struct GnapErrorCode(string Value)
{
    /// <summary>The request is malformed or missing a required parameter.</summary>
    public static GnapErrorCode InvalidRequest { get; } = new("invalid_request");

    /// <summary>The client was not recognized or its signature validation failed.</summary>
    public static GnapErrorCode InvalidClient { get; } = new("invalid_client");

    /// <summary>The interaction reference is incorrect or the interaction modes expired.</summary>
    public static GnapErrorCode InvalidInteraction { get; } = new("invalid_interaction");

    /// <summary>The flag configuration is not valid.</summary>
    public static GnapErrorCode InvalidFlag { get; } = new("invalid_flag");

    /// <summary>The token rotation request is not valid.</summary>
    public static GnapErrorCode InvalidRotation { get; } = new("invalid_rotation");

    /// <summary>The AS does not allow rotation of this access token's key.</summary>
    public static GnapErrorCode KeyRotationNotSupported { get; } = new("key_rotation_not_supported");

    /// <summary>The continuation of the referenced grant could not be processed.</summary>
    public static GnapErrorCode InvalidContinuation { get; } = new("invalid_continuation");

    /// <summary>The RO denied the request.</summary>
    public static GnapErrorCode UserDenied { get; } = new("user_denied");

    /// <summary>The request was denied for an unspecified reason.</summary>
    public static GnapErrorCode RequestDenied { get; } = new("request_denied");

    /// <summary>The presented user is not known or does not match the interacting user.</summary>
    public static GnapErrorCode UnknownUser { get; } = new("unknown_user");

    /// <summary>The interaction integrity could not be established.</summary>
    public static GnapErrorCode UnknownInteraction { get; } = new("unknown_interaction");

    /// <summary>The client did not respect the wait timeout before the next call.</summary>
    public static GnapErrorCode TooFast { get; } = new("too_fast");

    /// <summary>A limit on the total number of attempts has been reached.</summary>
    public static GnapErrorCode TooManyAttempts { get; } = new("too_many_attempts");

    /// <inheritdoc />
    public override string ToString() => Value;
}

/// <summary>
/// The <c>error</c> field of a grant response (RFC 9635 Section 3.6): either a
/// bare error code string or an object with <c>code</c> and <c>description</c>.
/// </summary>
[JsonConverter(typeof(GnapErrorConverter))]
public sealed class GnapError
{
    /// <summary>Creates an error with a code and optional developer-facing description.</summary>
    public GnapError(GnapErrorCode code, string? description = null)
    {
        Code = code;
        Description = description;
    }

    /// <summary>The machine-readable error code. Required.</summary>
    public GnapErrorCode Code { get; }

    /// <summary>A human-readable description for the client developer.</summary>
    public string? Description { get; }
}
