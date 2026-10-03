using System.Buffers.Text;
using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Gnap.Core;
using Gnap.Core.Json;
using Gnap.Core.Keys;
using Gnap.Core.Models;
using Gnap.Core.Proofing;
using Gnap.HttpMessageSignatures;

namespace Gnap.Client.Tests.Infrastructure;

/// <summary>
/// An in-memory GNAP AS (and a tiny RS) behind an <see cref="HttpMessageHandler"/>.
/// It verifies the httpsig key proof of every request it receives with the
/// Phase 0/1 verifier (shared nonce store, nonce required), so any unsigned,
/// mis-signed or replayed client request fails the test. Behaviour is scripted
/// through public properties and <see cref="Intercept"/>.
/// </summary>
internal sealed class FakeAuthorizationServer : HttpMessageHandler
{
    public const string AsBase = "https://as.example";
    public const string RsBase = "https://rs.example";

    private readonly InMemoryNonceStore _nonceStore = new();
    private readonly ConcurrentDictionary<string, Grant> _grants = new();
    private readonly ConcurrentDictionary<string, IssuedToken> _tokens = new();
    private readonly ConcurrentQueue<Func<HttpRequestMessage, HttpResponseMessage?>> _interceptors = new();
    private readonly object _gate = new();

    public FakeAuthorizationServer(VirtualTimeProvider time) => Time = time;

    public static Uri GrantEndpoint { get; } = new($"{AsBase}/tx");

    public static Uri ResourceUri { get; } = new($"{RsBase}/api/photos");

    public VirtualTimeProvider Time { get; }

    // ---- scripted behaviour -------------------------------------------------

    /// <summary>Issue tokens directly even when interaction was offered.</summary>
    public bool IssueImmediately { get; set; }

    /// <summary>The <c>wait</c> returned with each continuation (null: omit the field).</summary>
    public int? ContinueWait { get; set; } = 1;

    /// <summary>How many polls answer "still pending" after approval.</summary>
    public int PendingPolls { get; set; }

    /// <summary>The <c>expires_in</c> of issued tokens.</summary>
    public long? TokenLifetimeSeconds { get; set; } = 3600;

    /// <summary>Whether issued tokens carry a <c>manage</c> descriptor.</summary>
    public bool OfferTokenManagement { get; set; } = true;

    /// <summary>Whether the AS returns no <c>interact.finish</c> nonce.</summary>
    public bool OmitFinishNonce { get; set; }

    /// <summary>Enforce <c>wait</c> on polls with <c>too_fast</c>.</summary>
    public bool EnforceWait { get; set; } = true;

    /// <summary>Discovery answers carry <c>Cache-Control: max-age</c> when set.</summary>
    public int? DiscoveryMaxAge { get; set; }

    /// <summary>Instance identifiers known to the AS (by-reference clients).</summary>
    public Dictionary<string, JsonWebKey> RegisteredInstances { get; } = [];

    /// <summary>Key references known to the AS.</summary>
    public Dictionary<string, JsonWebKey> KeyReferences { get; } = [];

    // ---- observations -------------------------------------------------------

    public List<string> ProofFailures { get; } = [];

    public int VerifiedRequests { get; private set; }

    public List<(HttpMethod Method, string Path)> Requests { get; } = [];

    public int DiscoveryRequests { get; private set; }

    public GrantRequest? LastGrantRequest { get; private set; }

    public string? LastRotationSignatureInput { get; private set; }

    /// <summary>Runs before normal handling; return a response to short-circuit, null to pass.</summary>
    public void Intercept(Func<HttpRequestMessage, HttpResponseMessage?> interceptor) => _interceptors.Enqueue(interceptor);

    /// <summary>Fails the next matching request with a GNAP error.</summary>
    public void FailNext(string pathPrefix, GnapErrorCode code, HttpStatusCode status = HttpStatusCode.BadRequest, bool asObject = true) =>
        Intercept(request => request.RequestUri!.AbsolutePath.StartsWith(pathPrefix, StringComparison.Ordinal)
            ? ErrorResponse(code, status, asObject)
            : null);

    public Grant SingleGrant => _grants.Values.Single();

    // ---- simulated resource owner -------------------------------------------

    public InteractionFinishCallback Approve(bool tamperHash = false)
    {
        var grant = SingleGrant;
        grant.Approved = true;
        if (grant.ClientNonce is null)
        {
            return new InteractionFinishCallback { InteractRef = grant.InteractRef };
        }

        var hash = InteractionFinishHash.Compute(
            grant.ClientNonce, grant.AsNonce, grant.InteractRef, GrantEndpoint.AbsoluteUri, grant.HashMethod);
        if (tamperHash)
        {
            hash = InteractionFinishHash.Compute(
                grant.ClientNonce, grant.AsNonce, grant.InteractRef, "https://evil.example/tx", grant.HashMethod);
        }

        return new InteractionFinishCallback { Hash = hash, InteractRef = grant.InteractRef };
    }

    public Uri ApproveAndRedirect(bool tamperHash = false) =>
        Approve(tamperHash).ToRedirectUri(SingleGrant.FinishUri!);

    public void Deny() => SingleGrant.Denied = true;

    /// <summary>Lets every issued token expire server-side (the client still believes it valid).</summary>
    public void ExpireAllTokens()
    {
        foreach (var token in _tokens.Values)
        {
            token.ExpiredEarly = true;
        }
    }

    public IssuedToken? FindToken(string value) => _tokens.GetValueOrDefault(value);

    // ---- HTTP ---------------------------------------------------------------

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            Requests.Add((request.Method, request.RequestUri!.AbsolutePath));
        }

        while (_interceptors.TryPeek(out var interceptor))
        {
            HttpResponseMessage? intercepted;
            try
            {
                intercepted = interceptor(request);
            }
            catch
            {
                _interceptors.TryDequeue(out _);
                throw;
            }

            if (intercepted is null)
            {
                break;
            }

            _interceptors.TryDequeue(out _);
            return intercepted;
        }

        var body = request.Content is null ? [] : await request.Content.ReadAsByteArrayAsync(cancellationToken);
        var uri = request.RequestUri!;
        var path = uri.AbsolutePath;

        if (uri.Host == "rs.example")
        {
            return await HandleResourceAsync(request, body);
        }

        return (request.Method.Method, path) switch
        {
            ("OPTIONS", "/tx") => Discovery(),
            ("GET", "/.well-known/gnap-as-rs") => Discovery(),
            ("POST", "/tx") => await HandleGrantAsync(request, body),
            ("POST", _) when path.StartsWith("/continue/", StringComparison.Ordinal) => await HandleContinueAsync(request, body, path["/continue/".Length..]),
            ("DELETE", _) when path.StartsWith("/continue/", StringComparison.Ordinal) => await HandleCancelAsync(request, path["/continue/".Length..]),
            ("POST", _) when path.StartsWith("/token/", StringComparison.Ordinal) => await HandleRotateAsync(request, body, path["/token/".Length..]),
            ("DELETE", _) when path.StartsWith("/token/", StringComparison.Ordinal) => await HandleRevokeAsync(request, path["/token/".Length..]),
            _ => new HttpResponseMessage(HttpStatusCode.NotFound),
        };
    }

    private HttpResponseMessage Discovery()
    {
        DiscoveryRequests++;
        var json = """
            {
              "grant_request_endpoint": "https://as.example/tx",
              "interaction_start_modes_supported": ["redirect", "user_code", "user_code_uri"],
              "interaction_finish_methods_supported": ["redirect", "push"],
              "key_proofs_supported": ["httpsig"],
              "sub_id_formats_supported": ["opaque", "email"],
              "key_rotation_supported": true,
              "introspection_endpoint": "https://as.example/introspect"
            }
            """;
        var response = Json(HttpStatusCode.OK, json);
        if (DiscoveryMaxAge is { } maxAge)
        {
            response.Headers.CacheControl = new System.Net.Http.Headers.CacheControlHeaderValue { MaxAge = TimeSpan.FromSeconds(maxAge) };
        }

        return response;
    }

    private async Task<HttpResponseMessage> HandleGrantAsync(HttpRequestMessage request, byte[] body)
    {
        var grantRequest = JsonSerializer.Deserialize(body, GnapJsonContext.Default.GrantRequest);
        LastGrantRequest = grantRequest;
        if (grantRequest?.Client is not { } client)
        {
            return ErrorResponse(GnapErrorCode.InvalidRequest, HttpStatusCode.BadRequest);
        }

        JsonWebKey? jwk = client switch
        {
            { IsReference: true } => RegisteredInstances.GetValueOrDefault(client.Reference!),
            { Key.IsReference: true } => KeyReferences.GetValueOrDefault(client.Key.Reference!),
            _ => client.Key?.Jwk,
        };

        if (jwk is null)
        {
            return ErrorResponse(GnapErrorCode.InvalidClient, HttpStatusCode.BadRequest);
        }

        if (!await VerifyAsync(request, body, jwk))
        {
            return ErrorResponse(GnapErrorCode.InvalidClient, HttpStatusCode.Unauthorized);
        }

        var interact = grantRequest.Interact;
        if (interact is null || IssueImmediately)
        {
            return Json(HttpStatusCode.OK, new GrantResponse { AccessToken = IssueTokens(grantRequest, jwk) });
        }

        var grant = new Grant(NewValue(), jwk, grantRequest)
        {
            ClientNonce = interact.Finish?.Nonce,
            HashMethod = interact.Finish?.HashMethod,
            FinishUri = interact.Finish?.Uri,
            ContinueToken = NewValue(),
        };
        _grants[grant.Id] = grant;
        grant.NotBefore = Time.GetUtcNow() + TimeSpan.FromSeconds(ContinueWait ?? 5);

        var modes = interact.Start?.Select(s => s.Mode).ToHashSet() ?? [];
        return Json(HttpStatusCode.OK, new GrantResponse
        {
            Interact = new InteractResponse
            {
                Redirect = modes.Contains(StartModes.Redirect) ? $"{AsBase}/interact/{grant.Id}" : null,
                UserCode = modes.Contains(StartModes.UserCode) ? "A1BC-3DFF" : null,
                UserCodeUri = modes.Contains(StartModes.UserCodeUri) ? new UserCodeUri { Code = "A1BC-3DFF", Uri = $"{AsBase}/u" } : null,
                Finish = interact.Finish is not null && !OmitFinishNonce ? grant.AsNonce : null,
                ExpiresIn = 600,
            },
            Continue = ContinueFor(grant),
        });
    }

    private async Task<HttpResponseMessage> HandleContinueAsync(HttpRequestMessage request, byte[] body, string grantId)
    {
        if (!_grants.TryGetValue(grantId, out var grant))
        {
            return ErrorResponse(GnapErrorCode.InvalidContinuation, HttpStatusCode.NotFound);
        }

        if (request.Headers.Authorization?.ToString() != $"GNAP {grant.ContinueToken}")
        {
            return ErrorResponse(GnapErrorCode.InvalidContinuation, HttpStatusCode.Unauthorized);
        }

        if (!await VerifyAsync(request, body, grant.ClientKey))
        {
            return ErrorResponse(GnapErrorCode.InvalidClient, HttpStatusCode.Unauthorized);
        }

        if (EnforceWait && Time.GetUtcNow() < grant.NotBefore)
        {
            return ErrorResponse(GnapErrorCode.TooFast, HttpStatusCode.BadRequest);
        }

        if (grant.Denied)
        {
            _grants.TryRemove(grantId, out _);
            return ErrorResponse(GnapErrorCode.UserDenied, HttpStatusCode.BadRequest);
        }

        if (body.Length > 0)
        {
            var continueRequest = JsonSerializer.Deserialize(body, GnapJsonContext.Default.ContinueRequest);
            if (continueRequest?.InteractRef != grant.InteractRef || !grant.Approved)
            {
                return ErrorResponse(GnapErrorCode.InvalidInteraction, HttpStatusCode.BadRequest);
            }
        }

        if (!grant.Approved || PendingPolls > 0)
        {
            if (grant.Approved)
            {
                PendingPolls--;
            }

            // Still pending: rotate the continuation token, the client must adopt it.
            grant.ContinueToken = NewValue();
            grant.NotBefore = Time.GetUtcNow() + TimeSpan.FromSeconds(ContinueWait ?? 5);
            return Json(HttpStatusCode.OK, new GrantResponse { Continue = ContinueFor(grant) });
        }

        _grants.TryRemove(grantId, out _);
        return Json(HttpStatusCode.OK, new GrantResponse
        {
            AccessToken = IssueTokens(grant.Request, grant.ClientKey),
            InstanceId = "instance-" + grant.Id,
        });
    }

    private async Task<HttpResponseMessage> HandleCancelAsync(HttpRequestMessage request, string grantId)
    {
        if (!_grants.TryGetValue(grantId, out var grant)
            || request.Headers.Authorization?.ToString() != $"GNAP {grant.ContinueToken}")
        {
            return ErrorResponse(GnapErrorCode.InvalidContinuation, HttpStatusCode.Unauthorized);
        }

        if (!await VerifyAsync(request, [], grant.ClientKey))
        {
            return ErrorResponse(GnapErrorCode.InvalidClient, HttpStatusCode.Unauthorized);
        }

        _grants.TryRemove(grantId, out _);
        return new HttpResponseMessage(HttpStatusCode.NoContent);
    }

    private async Task<HttpResponseMessage> HandleRotateAsync(HttpRequestMessage request, byte[] body, string manageId)
    {
        var token = _tokens.Values.SingleOrDefault(t => t.ManageId == manageId && !t.Revoked);
        if (token is null || request.Headers.Authorization?.ToString() != $"GNAP {token.ManageToken}")
        {
            return ErrorResponse(GnapErrorCode.InvalidRotation, HttpStatusCode.Unauthorized);
        }

        if (!await VerifyAsync(request, body, token.ManagementKey))
        {
            return ErrorResponse(GnapErrorCode.InvalidClient, HttpStatusCode.Unauthorized);
        }

        var boundKey = token.BoundKey;
        var managementKey = token.ManagementKey;
        if (body.Length > 0)
        {
            // Key rotation (RFC 9635 Section 6.1.2): the new key must prove possession
            // too, with a signature covering the old key's signature.
            using var document = JsonDocument.Parse(body);
            var newKey = document.RootElement.GetProperty("key").Deserialize(GnapJsonContext.Default.GnapKey)!;
            LastRotationSignatureInput = string.Join(", ", request.Headers.GetValues("Signature-Input"));
            if (!LastRotationSignatureInput.Contains("\"signature\";key=\"sig1\"", StringComparison.Ordinal)
                || !await VerifyAsync(request, body, newKey.Jwk!))
            {
                return ErrorResponse(GnapErrorCode.InvalidRotation, HttpStatusCode.BadRequest);
            }

            boundKey = token.BoundKey is null ? null : newKey.Jwk;
            managementKey = newKey.Jwk!;
        }

        token.Revoked = true;
        var rotated = Issue(token.Access, boundKey, managementKey, token.Label);
        return Json(HttpStatusCode.OK, new GrantResponse { AccessToken = [rotated] });
    }

    private async Task<HttpResponseMessage> HandleRevokeAsync(HttpRequestMessage request, string manageId)
    {
        var token = _tokens.Values.SingleOrDefault(t => t.ManageId == manageId && !t.Revoked);
        if (token is null || request.Headers.Authorization?.ToString() != $"GNAP {token.ManageToken}")
        {
            return ErrorResponse(GnapErrorCode.InvalidRequest, HttpStatusCode.Unauthorized);
        }

        if (!await VerifyAsync(request, [], token.ManagementKey))
        {
            return ErrorResponse(GnapErrorCode.InvalidClient, HttpStatusCode.Unauthorized);
        }

        token.Revoked = true;
        return new HttpResponseMessage(HttpStatusCode.NoContent);
    }

    private async Task<HttpResponseMessage> HandleResourceAsync(HttpRequestMessage request, byte[] body)
    {
        if (!GnapAuthorization.TryParse(request.Headers.Authorization?.ToString(), out var value)
            || FindToken(value) is not { Revoked: false, ExpiredEarly: false } token
            || (token.ExpiresAt is { } expiresAt && Time.GetUtcNow() >= expiresAt))
        {
            var unauthorized = new HttpResponseMessage(HttpStatusCode.Unauthorized);
            unauthorized.Headers.TryAddWithoutValidation("WWW-Authenticate", $"GNAP as_uri=\"{GrantEndpoint}\", access=\"photo-api\"");
            return unauthorized;
        }

        if (token.BoundKey is not null && !await VerifyAsync(request, body, token.BoundKey))
        {
            return new HttpResponseMessage(HttpStatusCode.Unauthorized);
        }

        return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("photos") };
    }

    // ---- helpers ------------------------------------------------------------

    private async Task<bool> VerifyAsync(HttpRequestMessage request, byte[] body, JsonWebKey jwk)
    {
        var validator = new HttpSigKeyProofValidator
        {
            NonceStore = _nonceStore,
            RequireNonce = true,
            ExpectedKeyId = jwk.Kid,
            TimeProvider = Time,
        };

        var result = await validator.ValidateAsync(new KeyProofContext
        {
            Message = new HttpRequestMessageContext(request),
            Key = jwk.ToSignatureAlgorithm(),
            Content = body.Length > 0 ? body : null,
        });

        lock (_gate)
        {
            if (result.Succeeded)
            {
                VerifiedRequests++;
            }
            else
            {
                ProofFailures.Add($"{request.Method} {request.RequestUri}: {result.FailureReason}");
            }
        }

        return result.Succeeded;
    }

    private List<AccessTokenResponse> IssueTokens(GrantRequest request, JsonWebKey clientKey) =>
        request.AccessToken?
            .Select(t => Issue(t.Access, t.IsBearer ? null : clientKey, clientKey, t.Label))
            .ToList() ?? [];

    private AccessTokenResponse Issue(IList<AccessRight>? access, JsonWebKey? boundKey, JsonWebKey managementKey, string? label)
    {
        var token = new IssuedToken(NewValue(), NewValue(), NewValue(), boundKey, managementKey)
        {
            Access = access,
            Label = label,
            ExpiresAt = TokenLifetimeSeconds is { } seconds ? Time.GetUtcNow().AddSeconds(seconds) : null,
        };
        _tokens[token.Value] = token;
        return new AccessTokenResponse
        {
            Value = token.Value,
            Label = label,
            Access = access,
            ExpiresIn = TokenLifetimeSeconds,
            Flags = boundKey is null ? [AccessTokenFlags.Bearer] : null,
            Manage = OfferTokenManagement
                ? new TokenManagement
                {
                    Uri = $"{AsBase}/token/{token.ManageId}",
                    AccessToken = new AccessTokenResponse { Value = token.ManageToken },
                }
                : null,
        };
    }

    private ContinueResponse ContinueFor(Grant grant) => new()
    {
        Uri = $"{AsBase}/continue/{grant.Id}",
        Wait = ContinueWait,
        AccessToken = new AccessTokenResponse { Value = grant.ContinueToken },
    };

    public static HttpResponseMessage ErrorResponse(GnapErrorCode code, HttpStatusCode status, bool asObject = true) =>
        Json(status, asObject
            ? new GrantResponse { Error = new GnapError(code, $"scripted {code}") }
            : new GrantResponse { Error = new GnapError(code) });

    private static HttpResponseMessage Json(HttpStatusCode status, GrantResponse response) =>
        Json(status, JsonSerializer.Serialize(response, GnapJsonContext.Default.GrantResponse));

    private static HttpResponseMessage Json(HttpStatusCode status, string json) =>
        new(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    private static string NewValue() => Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(16));

    public sealed class Grant(string id, JsonWebKey clientKey, GrantRequest request)
    {
        public string Id { get; } = id;

        public JsonWebKey ClientKey { get; } = clientKey;

        public GrantRequest Request { get; } = request;

        public string AsNonce { get; } = NewValue();

        public string InteractRef { get; } = NewValue();

        public string? ClientNonce { get; init; }

        public string? HashMethod { get; init; }

        public string? FinishUri { get; init; }

        public required string ContinueToken { get; set; }

        public DateTimeOffset NotBefore { get; set; }

        public bool Approved { get; set; }

        public bool Denied { get; set; }
    }

    public sealed class IssuedToken(string value, string manageId, string manageToken, JsonWebKey? boundKey, JsonWebKey managementKey)
    {
        public string Value { get; } = value;

        public string ManageId { get; } = manageId;

        public string ManageToken { get; } = manageToken;

        public JsonWebKey? BoundKey { get; } = boundKey;

        public JsonWebKey ManagementKey { get; } = managementKey;

        public IList<AccessRight>? Access { get; init; }

        public string? Label { get; init; }

        public DateTimeOffset? ExpiresAt { get; init; }

        public bool Revoked { get; set; }

        public bool ExpiredEarly { get; set; }
    }
}
