using Xunit;

namespace Gnap.HttpMessageSignatures.Tests;

/// <summary>
/// Failure paths and canonicalization edge cases of <see cref="SignatureBaseBuilder"/>.
/// Each test pins the specific error so a mutated or swapped check is detected
/// (Stryker.NET mutation testing, see docs/mutation-testing.md).
/// </summary>
public class SignatureBaseBuilderErrorTests
{
    /// <summary>A hand-rolled message context that can leave any property empty.</summary>
    private sealed class BareMessage : IHttpMessageContext
    {
        public bool IsRequest { get; init; }

        public string? Method { get; init; }

        public Uri? TargetUri { get; init; }

        public int? StatusCode { get; init; }

        public IHttpMessageContext? AssociatedRequest { get; init; }

        public IReadOnlyList<string> GetFieldValues(string fieldName, bool fromTrailers = false) => [];
    }

    private static readonly SimpleHttpMessage Request = SimpleHttpMessage.Request("GET", "https://example.com/");

    private static string BuildError(IHttpMessageContext message, SignatureComponent component) =>
        Assert.Throws<HttpMessageSignatureException>(
            () => SignatureBaseBuilder.Build(message, new SignatureParameters().AddComponent(component))).Message;

    [Fact]
    public void NullArguments_Throw()
    {
        Assert.Throws<ArgumentNullException>("message", () => SignatureBaseBuilder.Build(null!, new SignatureParameters()));
        Assert.Throws<ArgumentNullException>("parameters", () => SignatureBaseBuilder.Build(Request, null!));
    }

    [Fact]
    public void ReqFlagOnRequest_NamesTheFlag()
    {
        var error = BuildError(Request, SignatureComponent.Method.WithRequest());

        Assert.Equal("Component \"@method\";req uses the 'req' flag, which is only valid when signing a response.", error);
    }

    [Fact]
    public void ReqFlagWithoutAssociatedRequest_Throws()
    {
        var error = BuildError(SimpleHttpMessage.Response(200), SignatureComponent.Method.WithRequest());

        Assert.Equal("The response has no associated request for a 'req' component.", error);
    }

    [Fact]
    public void StatusOnRequest_IsRejectedAsResponseOnly()
    {
        var error = BuildError(Request, SignatureComponent.Status);

        Assert.Equal("@status is only defined for response messages.", error);
    }

    [Fact]
    public void StatusWithReqFlag_IsRejectedAsResponseOnly()
    {
        var response = SimpleHttpMessage.Response(200, Request);

        var error = BuildError(response, SignatureComponent.Status.WithRequest());

        Assert.Equal("@status is only defined for response messages.", error);
    }

    [Fact]
    public void ResponseWithoutStatusCode_Throws()
    {
        var error = BuildError(new BareMessage { IsRequest = false }, SignatureComponent.Status);

        Assert.Equal("The response has no status code.", error);
    }

    [Fact]
    public void RequestDerivedComponentOnResponse_RequiresReqFlag()
    {
        var error = BuildError(SimpleHttpMessage.Response(200, Request), SignatureComponent.Method);

        Assert.Equal("Derived component @method on a response requires the 'req' flag.", error);
    }

    [Fact]
    public void RequestWithoutTargetUri_Throws()
    {
        var error = BuildError(new BareMessage { IsRequest = true, Method = "GET" }, SignatureComponent.Method);

        Assert.Equal("The request has no target URI.", error);
    }

    [Fact]
    public void RequestWithoutMethod_Throws()
    {
        var message = new BareMessage { IsRequest = true, TargetUri = new Uri("https://example.com/") };

        var error = BuildError(message, SignatureComponent.Method);

        Assert.Equal("The request has no method.", error);
    }

    [Fact]
    public void UnknownDerivedComponent_Throws()
    {
        var error = BuildError(Request, SignatureComponent.Derived("@unknown"));

        Assert.Equal("Unknown derived component @unknown.", error);
    }

    [Fact]
    public void MissingHeaderField_NamesHeaders()
    {
        var error = BuildError(Request, SignatureComponent.Field("x-missing"));

        Assert.Equal("Field 'x-missing' is not present in the message headers.", error);
    }

    [Fact]
    public void MissingTrailerField_NamesTrailers()
    {
        var message = SimpleHttpMessage.Request("GET", "https://example.com/").WithHeader("X-Field", "only a header");

        var error = BuildError(message, SignatureComponent.Field("x-field").WithTrailers());

        Assert.Equal("Field 'x-field' is not present in the message trailers.", error);
    }

    [Fact]
    public void TrailerField_IsTakenFromTrailers()
    {
        var message = SimpleHttpMessage.Request("GET", "https://example.com/")
            .WithHeader("X-Field", "header value")
            .WithTrailer("X-Field", "trailer value");
        var parameters = new SignatureParameters().AddComponent(SignatureComponent.Field("x-field").WithTrailers());

        var actual = SignatureBaseBuilder.Build(message, parameters);

        Assert.StartsWith("\"x-field\";tr: trailer value\n", actual, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void BsCombinedWithSfOrKey_IsRejected(bool sf, bool key)
    {
        var component = SignatureComponent.Field("content-digest").WithByteSequenceEncoding();
        component = sf ? component.WithStructuredFieldSerialization() : component;
        component = key ? component.WithKey("sha-256") : component;
        var message = SimpleHttpMessage.Request("GET", "https://example.com/").WithHeader("Content-Digest", "sha-256=:AA==:");

        var error = BuildError(message, component);

        Assert.Equal("The 'bs' flag cannot be combined with 'sf' or 'key'.", error);
    }

    [Fact]
    public void SfOnUnregisteredField_Throws()
    {
        var message = SimpleHttpMessage.Request("GET", "https://example.com/").WithHeader("X-Unregistered-Sf", "a=1");

        var error = BuildError(message, SignatureComponent.Field("x-unregistered-sf").WithStructuredFieldSerialization());

        Assert.Equal(
            "Field 'x-unregistered-sf' is covered with 'sf' or 'key' but its structured field type is not registered in SignatureBaseBuilder.FieldTypes.",
            error);
    }

    [Fact]
    public void KeyForMissingDictionaryMember_Throws()
    {
        var message = SimpleHttpMessage.Request("GET", "https://example.com/").WithHeader("Content-Digest", "sha-256=:AA==:");

        var error = BuildError(message, SignatureComponent.Field("content-digest").WithKey("sha-512"));

        Assert.Equal("Dictionary field 'content-digest' has no member 'sha-512'.", error);
    }

    [Fact]
    public void SfOnList_ReserializesCanonically()
    {
        SignatureBaseBuilder.FieldTypes.Register("x-mut-list", StructuredFieldType.List);
        var message = SimpleHttpMessage.Request("GET", "https://example.com/")
            .WithHeader("X-Mut-List", "a,   b;x=1")
            .WithHeader("X-Mut-List", "  (c   d)");
        var parameters = new SignatureParameters()
            .AddComponent(SignatureComponent.Field("x-mut-list").WithStructuredFieldSerialization());

        var actual = SignatureBaseBuilder.Build(message, parameters);

        Assert.StartsWith("\"x-mut-list\";sf: a, b;x=1, (c d)\n", actual, StringComparison.Ordinal);
    }

    [Fact]
    public void SfOnItem_ReserializesCanonically()
    {
        SignatureBaseBuilder.FieldTypes.Register("x-mut-item", StructuredFieldType.Item);
        var message = SimpleHttpMessage.Request("GET", "https://example.com/").WithHeader("X-Mut-Item", "  token;a=?1  ");
        var parameters = new SignatureParameters()
            .AddComponent(SignatureComponent.Field("x-mut-item").WithStructuredFieldSerialization());

        var actual = SignatureBaseBuilder.Build(message, parameters);

        Assert.StartsWith("\"x-mut-item\";sf: token;a\n", actual, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("x-mut-list", StructuredFieldType.List)]
    [InlineData("x-mut-item", StructuredFieldType.Item)]
    public void KeyOnNonDictionary_Throws(string fieldName, StructuredFieldType type)
    {
        SignatureBaseBuilder.FieldTypes.Register(fieldName, type);
        var message = SimpleHttpMessage.Request("GET", "https://example.com/").WithHeader(fieldName, "a");

        var error = BuildError(message, SignatureComponent.Field(fieldName).WithKey("a"));

        Assert.Equal($"The 'key' parameter requires field '{fieldName}' to be a dictionary.", error);
    }

    [Fact]
    public void SfOnInvalidStructuredField_Throws()
    {
        var message = SimpleHttpMessage.Request("GET", "https://example.com/").WithHeader("Content-Digest", "not a dictionary!");

        var exception = Assert.Throws<HttpMessageSignatureException>(() => SignatureBaseBuilder.Build(
            message,
            new SignatureParameters().AddComponent(SignatureComponent.Field("content-digest").WithStructuredFieldSerialization())));

        Assert.StartsWith("Field 'content-digest' is not a valid structured field: ", exception.Message, StringComparison.Ordinal);
        Assert.IsType<Gnap.HttpMessageSignatures.StructuredFields.SfParseException>(exception.InnerException);
    }

    [Theory]
    [InlineData("first\r\n  second", "first second")]
    [InlineData("first\n\tsecond", "first second")]
    [InlineData("first\r second", "first second")]
    [InlineData("a\r\n b\n c\r d", "a b c d")]
    public void LineBreaks_AreCollapsedToSingleSpaces(string raw, string expected)
    {
        var message = SimpleHttpMessage.Request("GET", "https://example.com/").WithHeader("X-Folded", raw);
        var parameters = new SignatureParameters().AddComponent(SignatureComponent.Field("x-folded"));

        var actual = SignatureBaseBuilder.Build(message, parameters);

        Assert.StartsWith($"\"x-folded\": {expected}\n", actual, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("signature")]
    [InlineData("signature-input")]
    [InlineData("content-digest")]
    [InlineData("repr-digest")]
    [InlineData("want-content-digest")]
    [InlineData("want-repr-digest")]
    [InlineData("accept-signature")]
    [InlineData("cache-control")]
    [InlineData("priority")]
    public void WellKnownFields_AreRegisteredAsDictionaries(string fieldName)
    {
        Assert.Equal(StructuredFieldType.Dictionary, new StructuredFieldRegistry().Get(fieldName));
        Assert.Equal(StructuredFieldType.Dictionary, new StructuredFieldRegistry().Get(fieldName.ToUpperInvariant()));
    }

    [Fact]
    public void UnknownField_IsNotRegistered()
    {
        Assert.Null(new StructuredFieldRegistry().Get("x-not-registered"));
        Assert.Null(new StructuredFieldRegistry().Get(string.Empty));
    }
}
