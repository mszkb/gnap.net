using System.Text.Json;
using System.Text.Json.Nodes;
using Gnap.Core.Json;
using Gnap.Core.Keys;
using Gnap.Core.Models;
using Xunit;

namespace Gnap.Core.Tests;

public class JsonModelTests
{
    // The non-normative grant request example of RFC 9635 Section 2 (key value shortened).
    private const string SpecGrantRequest = /*lang=json,strict*/ """
        {
            "access_token": {
                "access": [
                    {
                        "type": "photo-api",
                        "actions": ["read", "write", "dolphin"],
                        "locations": ["https://server.example.net/", "https://resource.local/other"],
                        "datatypes": ["metadata", "images"]
                    },
                    "dolphin-metadata"
                ]
            },
            "client": {
                "display": {
                    "name": "My Client Display Name",
                    "uri": "https://example.net/client"
                },
                "key": {
                    "proof": "httpsig",
                    "jwk": {
                        "kty": "RSA",
                        "e": "AQAB",
                        "kid": "xyz-1",
                        "alg": "RS256",
                        "n": "kOB5rR4Jv0GMeL"
                    }
                }
            },
            "interact": {
                "start": ["redirect"],
                "finish": {
                    "method": "redirect",
                    "uri": "https://client.example.net/return/123455",
                    "nonce": "LKLTI25DK82FX4T4QFZC"
                }
            },
            "subject": {
                "sub_id_formats": ["iss_sub", "opaque"],
                "assertion_formats": ["id_token"]
            }
        }
        """;

    [Fact]
    public void SpecGrantRequest_Parses()
    {
        var request = GnapJson.DeserializeGrantRequest(SpecGrantRequest)!;

        var token = Assert.Single(request.AccessToken!);
        Assert.Equal(2, token.Access!.Count);
        Assert.False(token.Access[0].IsReference);
        Assert.Equal("photo-api", token.Access[0].Type);
        Assert.Equal(["read", "write", "dolphin"], token.Access[0].Actions);
        Assert.True(token.Access[1].IsReference);
        Assert.Equal("dolphin-metadata", token.Access[1].Reference);

        Assert.False(request.Client!.IsReference);
        Assert.Equal("My Client Display Name", request.Client.Display!.Name);
        Assert.Equal(ProofMethod.Methods.HttpSig, request.Client.Key!.Proof!.Method);
        Assert.Equal("xyz-1", request.Client.Key.Jwk!.Kid);
        Assert.Equal("RS256", request.Client.Key.Jwk.Alg);

        var startMode = Assert.Single(request.Interact!.Start!);
        Assert.Equal(StartModes.Redirect, startMode.Mode);
        Assert.Equal(FinishMethods.Redirect, request.Interact.Finish!.Method);
        Assert.Equal("LKLTI25DK82FX4T4QFZC", request.Interact.Finish.Nonce);
        Assert.Null(request.Interact.Finish.HashMethod);

        Assert.Equal(["iss_sub", "opaque"], request.Subject!.SubIdFormats);
        Assert.Equal(["id_token"], request.Subject.AssertionFormats);
    }

    [Fact]
    public void SpecGrantRequest_RoundTripsLosslessly()
    {
        var request = GnapJson.DeserializeGrantRequest(SpecGrantRequest)!;
        var serialized = GnapJson.Serialize(request);

        Assert.True(
            JsonNode.DeepEquals(JsonNode.Parse(SpecGrantRequest), JsonNode.Parse(serialized)),
            $"Round-tripped JSON differs:\n{serialized}");
    }

    [Fact]
    public void SingleAccessTokenRequest_SerializesAsObject()
    {
        var request = new GrantRequest
        {
            AccessToken = [new AccessTokenRequest { Access = [AccessRight.ForReference("finance")] }],
        };

        var node = JsonNode.Parse(GnapJson.Serialize(request))!;
        Assert.IsType<JsonObject>(node["access_token"]);
    }

    [Fact]
    public void MultipleAccessTokenRequests_SerializeAsArray()
    {
        var request = new GrantRequest
        {
            AccessToken =
            [
                new AccessTokenRequest { Label = "token1", Access = [AccessRight.ForReference("finance")] },
                new AccessTokenRequest { Label = "token2", Access = [AccessRight.ForReference("medical")] },
            ],
        };

        var node = JsonNode.Parse(GnapJson.Serialize(request))!;
        var array = Assert.IsType<JsonArray>(node["access_token"]);
        Assert.Equal(2, array.Count);

        var parsed = GnapJson.DeserializeGrantRequest(node.ToJsonString())!;
        Assert.Equal(2, parsed.AccessToken!.Count);
        Assert.Equal("token1", parsed.AccessToken[0].Label);
    }

    [Fact]
    public void ClientAndKeyReferences_RoundTrip()
    {
        var json = /*lang=json,strict*/ """{"client":"client-541-ab"}""";
        var request = GnapJson.DeserializeGrantRequest(json)!;
        Assert.True(request.Client!.IsReference);
        Assert.Equal("client-541-ab", request.Client.Reference);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(json), JsonNode.Parse(GnapJson.Serialize(request))));

        var keyJson = /*lang=json,strict*/ """{"client":{"key":"S-P4XJQ_RYJCRTSU1.63N3E"}}""";
        var keyRequest = GnapJson.DeserializeGrantRequest(keyJson)!;
        Assert.True(keyRequest.Client!.Key!.IsReference);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(keyJson), JsonNode.Parse(GnapJson.Serialize(keyRequest))));
    }

    [Fact]
    public void UserReferenceAndObject_RoundTrip()
    {
        var byReference = GnapJson.DeserializeGrantRequest(/*lang=json,strict*/ """{"user":"XUT2MFM1XBIKJKSDU8QM"}""")!;
        Assert.Equal("XUT2MFM1XBIKJKSDU8QM", byReference.User!.Reference);

        var json = /*lang=json,strict*/ """
            {"user":{"sub_ids":[{"format":"opaque","id":"J2G8G8O4AZ"}],"assertions":[{"format":"id_token","value":"eyj..."}]}}
            """;
        var byValue = GnapJson.DeserializeGrantRequest(json)!;
        var subId = Assert.Single(byValue.User!.SubIds!);
        Assert.Equal(SubjectIdentifierFormats.Opaque, subId.Format);
        Assert.Equal("J2G8G8O4AZ", subId.Id);
        var assertion = Assert.Single(byValue.User.Assertions!);
        Assert.Equal(AssertionFormats.IdToken, assertion.Format);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(json), JsonNode.Parse(GnapJson.Serialize(byValue))));
    }

    [Fact]
    public void GrantResponse_Parses()
    {
        var json = /*lang=json,strict*/ """
            {
                "interact": {
                    "redirect": "https://server.example.com/interact/4CF492MLVMSW9MKMXKHQ",
                    "finish": "MBDOFXG4Y5CVJCX821LH"
                },
                "continue": {
                    "access_token": { "value": "80UPRY5NM33OMUKMKSKU" },
                    "uri": "https://server.example.com/tx",
                    "wait": 60
                },
                "instance_id": "7C7C4AZ9KHRS6X63AJAO"
            }
            """;

        var response = GnapJson.DeserializeGrantResponse(json)!;
        Assert.Equal("MBDOFXG4Y5CVJCX821LH", response.Interact!.Finish);
        Assert.Equal("80UPRY5NM33OMUKMKSKU", response.Continue!.AccessToken!.Value);
        Assert.Equal(TimeSpan.FromSeconds(60), response.Continue.EffectiveWait);
        Assert.Equal("7C7C4AZ9KHRS6X63AJAO", response.InstanceId);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(json), JsonNode.Parse(GnapJson.Serialize(response))));
    }

    [Fact]
    public void ContinueWait_DefaultsToFiveSeconds()
    {
        var response = GnapJson.DeserializeGrantResponse(/*lang=json,strict*/ """{"continue":{"uri":"https://as.example/c"}}""")!;
        Assert.Equal(TimeSpan.FromSeconds(5), response.Continue!.EffectiveWait);
    }

    [Fact]
    public void AccessTokenResponse_BearerAndBinding()
    {
        var json = /*lang=json,strict*/ """
            {
                "access_token": {
                    "value": "OS9M2PMHKUR64TB8N6BW7OZB8CDFONP219RP1LT0",
                    "flags": ["bearer", "durable"],
                    "manage": {
                        "uri": "https://server.example.com/token/PRY5NM33O",
                        "access_token": { "value": "B8CDFONP21-4TB8N6.BW7ONM" }
                    },
                    "access": ["finance", "medical"],
                    "expires_in": 3600
                }
            }
            """;

        var response = GnapJson.DeserializeGrantResponse(json)!;
        var token = Assert.Single(response.AccessToken!);
        Assert.True(token.IsBearer);
        Assert.True(token.IsDurable);
        Assert.False(token.IsBoundToClientKey);
        Assert.Equal(3600, token.ExpiresIn);
        Assert.Equal("https://server.example.com/token/PRY5NM33O", token.Manage!.Uri);
        Assert.Equal("B8CDFONP21-4TB8N6.BW7ONM", token.Manage.AccessToken!.Value);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(json), JsonNode.Parse(GnapJson.Serialize(response))));

        var boundToken = GnapJson.DeserializeGrantResponse(/*lang=json,strict*/ """{"access_token":{"value":"X"}}""")!
            .AccessToken![0];
        Assert.True(boundToken.IsBoundToClientKey);
    }

    [Fact]
    public void Error_StringAndObjectForms_Parse()
    {
        var fromString = GnapJson.DeserializeGrantResponse(/*lang=json,strict*/ """{"error":"user_denied"}""")!;
        Assert.Equal(GnapErrorCode.UserDenied, fromString.Error!.Code);
        Assert.Null(fromString.Error.Description);

        var fromObject = GnapJson.DeserializeGrantResponse(
            /*lang=json,strict*/ """{"error":{"code":"user_denied","description":"The RO denied the request"}}""")!;
        Assert.Equal(GnapErrorCode.UserDenied, fromObject.Error!.Code);
        Assert.Equal("The RO denied the request", fromObject.Error.Description);

        // Compact string form is written when there is no description, object form otherwise.
        Assert.Contains("\"error\":\"user_denied\"", GnapJson.Serialize(fromString), StringComparison.Ordinal);
        Assert.Contains("\"code\":\"user_denied\"", GnapJson.Serialize(fromObject), StringComparison.Ordinal);
    }

    [Fact]
    public void UnknownMembers_AreTolerated_AndPreserved()
    {
        var json = /*lang=json,strict*/ """
            {
                "client": "client-1",
                "future_field": { "nested": [1, 2, 3] }
            }
            """;

        var request = GnapJson.DeserializeGrantRequest(json)!;
        Assert.True(request.AdditionalFields!.ContainsKey("future_field"));
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(json), JsonNode.Parse(GnapJson.Serialize(request))));
    }

    [Fact]
    public void AccessRight_ApiSpecificFields_ArePreserved()
    {
        var json = /*lang=json,strict*/ """
            {
                "access_token": {
                    "access": [
                        {
                            "type": "financial-transaction",
                            "actions": ["withdraw"],
                            "identifier": "account-14-32-32-3",
                            "currency": "USD"
                        }
                    ]
                },
                "client": "client-1"
            }
            """;

        var request = GnapJson.DeserializeGrantRequest(json)!;
        var right = request.AccessToken![0].Access![0];
        Assert.Equal("financial-transaction", right.Type);
        Assert.Equal("account-14-32-32-3", right.Identifier);
        Assert.Equal("USD", right.AdditionalFields!["currency"].GetString());
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(json), JsonNode.Parse(GnapJson.Serialize(request))));
    }

    [Fact]
    public void ProofMethod_ObjectForm_RoundTrips()
    {
        var json = /*lang=json,strict*/ """
            {"client":{"key":{"proof":{"method":"httpsig","alg":"ecdsa-p384-sha384","content-digest-alg":"sha-512"}}}}
            """;

        var request = GnapJson.DeserializeGrantRequest(json)!;
        var proof = request.Client!.Key!.Proof!;
        Assert.Equal(ProofMethod.Methods.HttpSig, proof.Method);
        Assert.Equal("ecdsa-p384-sha384", proof.GetParameter("alg"));
        Assert.Equal("sha-512", proof.GetParameter("content-digest-alg"));
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(json), JsonNode.Parse(GnapJson.Serialize(request))));
    }

    [Fact]
    public void StartMode_ObjectForm_RoundTrips()
    {
        var json = /*lang=json,strict*/ """
            {"interact":{"start":["redirect",{"mode":"custom_mode","param":"value"}]}}
            """;

        var request = GnapJson.DeserializeGrantRequest(json)!;
        Assert.Equal(2, request.Interact!.Start!.Count);
        Assert.Equal("redirect", request.Interact.Start[0].Mode);
        Assert.Equal("custom_mode", request.Interact.Start[1].Mode);
        Assert.Equal("value", request.Interact.Start[1].Parameters!["param"].GetString());
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(json), JsonNode.Parse(GnapJson.Serialize(request))));
    }

    [Fact]
    public void SubjectResponse_ParsesUpdatedAt()
    {
        var json = /*lang=json,strict*/ """
            {
                "subject": {
                    "sub_ids": [
                        {"format": "opaque", "id": "J2G8G8O4AZ"},
                        {"format": "email", "email": "user@example.com"},
                        {"format": "iss_sub", "iss": "https://as.example", "sub": "user-1"}
                    ],
                    "updated_at": "2026-07-01T12:30:00+00:00"
                }
            }
            """;

        var response = GnapJson.DeserializeGrantResponse(json)!;
        Assert.Equal(3, response.Subject!.SubIds!.Count);
        Assert.Equal("user@example.com", response.Subject.SubIds[1].Email);
        Assert.Equal("https://as.example", response.Subject.SubIds[2].Iss);
        Assert.Equal(new DateTimeOffset(2026, 7, 1, 12, 30, 0, TimeSpan.Zero), response.Subject.UpdatedAt);
    }

    [Fact]
    public void ContinueRequest_RoundTrips()
    {
        var request = new ContinueRequest { InteractRef = "4IFWWIKYBC2PQ6U56NL1" };
        var json = GnapJson.Serialize(request);
        Assert.Equal(/*lang=json,strict*/ """{"interact_ref":"4IFWWIKYBC2PQ6U56NL1"}""", json);
        Assert.Equal("4IFWWIKYBC2PQ6U56NL1", GnapJson.DeserializeContinueRequest(json)!.InteractRef);
    }

    [Fact]
    public void UserCodeUriResponse_Parses()
    {
        var json = /*lang=json,strict*/ """
            {"interact":{"user_code_uri":{"code":"A1BC3DFF","uri":"https://s.example/device"},"expires_in":600}}
            """;

        var response = GnapJson.DeserializeGrantResponse(json)!;
        Assert.Equal("A1BC3DFF", response.Interact!.UserCodeUri!.Code);
        Assert.Equal("https://s.example/device", response.Interact.UserCodeUri.Uri);
        Assert.Equal(600, response.Interact.ExpiresIn);
    }

    [Fact]
    public void NullsAreOmitted_WhenSerializing()
    {
        var request = new GrantRequest { Client = ClientInstance.ForReference("c1") };
        Assert.Equal(/*lang=json,strict*/ """{"client":"c1"}""", GnapJson.Serialize(request));
    }

    [Fact]
    public void MalformedUnion_Throws()
    {
        Assert.Throws<JsonException>(() => GnapJson.DeserializeGrantRequest(/*lang=json,strict*/ """{"client":42}"""));
        Assert.Throws<JsonException>(() => GnapJson.DeserializeGrantResponse(/*lang=json,strict*/ """{"error":{"description":"no code"}}"""));
        Assert.Throws<JsonException>(() => GnapJson.DeserializeGrantRequest(/*lang=json,strict*/ """{"interact":{"start":[{"param":"missing mode"}]}}"""));
    }
}
