using Gnap.HttpMessageSignatures.StructuredFields;
using Xunit;

namespace Gnap.HttpMessageSignatures.Tests;

/// <summary>
/// Checks that the canonical signature base exactly matches the bases printed in
/// RFC 9421 Appendix B and exercises the derived-component and field
/// canonicalization rules of Section 2.
/// </summary>
public class SignatureBaseBuilderTests
{
    private static SignatureParameters ParseParameters(string signatureInputValue)
    {
        var dictionary = SfParser.ParseDictionary(signatureInputValue);
        var member = Assert.IsType<SfInnerList>(dictionary[0].Value);
        return SignatureParameters.FromSfInnerList(member);
    }

    [Theory]
    [InlineData(Rfc9421TestVectors.B21SignatureInput, Rfc9421TestVectors.B21ExpectedBase)]
    [InlineData(Rfc9421TestVectors.B22SignatureInput, Rfc9421TestVectors.B22ExpectedBase)]
    [InlineData(Rfc9421TestVectors.B23SignatureInput, Rfc9421TestVectors.B23ExpectedBase)]
    [InlineData(Rfc9421TestVectors.B25SignatureInput, Rfc9421TestVectors.B25ExpectedBase)]
    [InlineData(Rfc9421TestVectors.B26SignatureInput, Rfc9421TestVectors.B26ExpectedBase)]
    public void RequestBases_MatchAppendixB(string signatureInput, string expectedBase)
    {
        var parameters = ParseParameters(signatureInput);

        var actual = SignatureBaseBuilder.Build(Rfc9421TestVectors.TestRequest(), parameters);

        Assert.Equal(expectedBase, actual);
    }

    [Fact]
    public void ResponseBase_MatchesAppendixB24()
    {
        var parameters = ParseParameters(Rfc9421TestVectors.B24SignatureInput);

        var actual = SignatureBaseBuilder.Build(Rfc9421TestVectors.TestResponse(), parameters);

        Assert.Equal(Rfc9421TestVectors.B24ExpectedBase, actual);
    }

    [Fact]
    public void TransformBase_CollapsesMultiValueAcceptHeader()
    {
        var parameters = ParseParameters(Rfc9421TestVectors.TransformSignatureInput);

        var actual = SignatureBaseBuilder.Build(Rfc9421TestVectors.TransformRequest(), parameters);

        Assert.Equal(Rfc9421TestVectors.TransformExpectedBase, actual);
    }

    [Fact]
    public void DerivedComponents_ResolvePerSection22()
    {
        var request = SimpleHttpMessage.Request("get", "https://www.Example.com:443/path/sub?q=1");
        var parameters = new SignatureParameters().AddComponents(
        [
            SignatureComponent.Method,
            SignatureComponent.TargetUri,
            SignatureComponent.Authority,
            SignatureComponent.Scheme,
            SignatureComponent.RequestTarget,
            SignatureComponent.Path,
            SignatureComponent.Query,
        ]);

        var actual = SignatureBaseBuilder.Build(request, parameters);

        Assert.Equal(
            "\"@method\": GET\n" +
            "\"@target-uri\": https://www.example.com/path/sub?q=1\n" +
            "\"@authority\": www.example.com\n" +
            "\"@scheme\": https\n" +
            "\"@request-target\": /path/sub?q=1\n" +
            "\"@path\": /path/sub\n" +
            "\"@query\": ?q=1\n" +
            "\"@signature-params\": (\"@method\" \"@target-uri\" \"@authority\" \"@scheme\" \"@request-target\" \"@path\" \"@query\")",
            actual);
    }

    [Fact]
    public void NonDefaultPort_IsPartOfAuthority()
    {
        var request = SimpleHttpMessage.Request("GET", "https://example.com:8443/");
        var parameters = new SignatureParameters().AddComponent(SignatureComponent.Authority);

        var actual = SignatureBaseBuilder.Build(request, parameters);

        Assert.Equal("\"@authority\": example.com:8443\n\"@signature-params\": (\"@authority\")", actual);
    }

    [Fact]
    public void EmptyQuery_SerializesAsLoneQuestionMark()
    {
        var request = SimpleHttpMessage.Request("GET", "https://example.com/path");
        var parameters = new SignatureParameters().AddComponent(SignatureComponent.Query);

        var actual = SignatureBaseBuilder.Build(request, parameters);

        Assert.Equal("\"@query\": ?\n\"@signature-params\": (\"@query\")", actual);
    }

    [Fact]
    public void QueryParam_DecodesAndStrictlyReencodes()
    {
        // '+' means space in form encoding; the space is then strictly re-encoded as %20.
        var request = SimpleHttpMessage.Request("GET", "https://example.com/?greeting=hello+w%C3%B6rld");
        var parameters = new SignatureParameters().AddComponent(SignatureComponent.QueryParam("greeting"));

        var actual = SignatureBaseBuilder.Build(request, parameters);

        Assert.Equal(
            "\"@query-param\";name=\"greeting\": hello%20w%C3%B6rld\n" +
            "\"@signature-params\": (\"@query-param\";name=\"greeting\")",
            actual);
    }

    [Fact]
    public void RepeatedQueryParam_EmitsOneLinePerOccurrence()
    {
        var request = SimpleHttpMessage.Request("GET", "https://example.com/?id=1&id=2");
        var parameters = new SignatureParameters().AddComponent(SignatureComponent.QueryParam("id"));

        var actual = SignatureBaseBuilder.Build(request, parameters);

        Assert.Equal(
            "\"@query-param\";name=\"id\": 1\n" +
            "\"@query-param\";name=\"id\": 2\n" +
            "\"@signature-params\": (\"@query-param\";name=\"id\")",
            actual);
    }

    [Fact]
    public void FieldValues_AreTrimmedAndJoined()
    {
        var request = SimpleHttpMessage.Request("GET", "https://example.com/")
            .WithHeader("X-Custom", "  first value\t")
            .WithHeader("X-Custom", "second");
        var parameters = new SignatureParameters().AddComponent(SignatureComponent.Field("x-custom"));

        var actual = SignatureBaseBuilder.Build(request, parameters);

        Assert.Equal("\"x-custom\": first value, second\n\"@signature-params\": (\"x-custom\")", actual);
    }

    [Fact]
    public void ObsFold_IsCollapsedToSingleSpaces()
    {
        var request = SimpleHttpMessage.Request("GET", "https://example.com/")
            .WithHeader("X-Obs-Fold-Header", "Obsolete\n    line folding");
        var parameters = new SignatureParameters().AddComponent(SignatureComponent.Field("x-obs-fold-header"));

        var actual = SignatureBaseBuilder.Build(request, parameters);

        Assert.Equal("\"x-obs-fold-header\": Obsolete line folding\n\"@signature-params\": (\"x-obs-fold-header\")", actual);
    }

    [Fact]
    public void SfFlag_ReserializesDictionaryCanonically()
    {
        SignatureBaseBuilder.FieldTypes.Register("example-dict", StructuredFieldType.Dictionary);
        var request = SimpleHttpMessage.Request("GET", "https://example.com/")
            .WithHeader("Example-Dict", " a=1,    b=2;x=1;y=2,   c=(a   b   c)");
        var parameters = new SignatureParameters()
            .AddComponent(SignatureComponent.Field("example-dict").WithStructuredFieldSerialization());

        var actual = SignatureBaseBuilder.Build(request, parameters);

        Assert.StartsWith("\"example-dict\";sf: a=1, b=2;x=1;y=2, c=(a b c)\n", actual, StringComparison.Ordinal);
    }

    [Fact]
    public void KeyParameter_ExtractsSingleDictionaryMember()
    {
        SignatureBaseBuilder.FieldTypes.Register("example-dict", StructuredFieldType.Dictionary);
        var request = SimpleHttpMessage.Request("GET", "https://example.com/")
            .WithHeader("Example-Dict", " a=1, b=2;x=1;y=2, c=(a b c), d");
        var parameters = new SignatureParameters()
            .AddComponent(SignatureComponent.Field("example-dict").WithKey("d"));

        var actual = SignatureBaseBuilder.Build(request, parameters);

        Assert.StartsWith("\"example-dict\";key=\"d\": ?1\n", actual, StringComparison.Ordinal);
    }

    [Fact]
    public void BsFlag_WrapsEachValueAsByteSequence()
    {
        var request = SimpleHttpMessage.Request("GET", "https://example.com/")
            .WithHeader("X-Empty", "value, with, lots, of, commas")
            .WithHeader("X-Empty", "another value");
        var parameters = new SignatureParameters()
            .AddComponent(SignatureComponent.Field("x-empty").WithByteSequenceEncoding());

        var actual = SignatureBaseBuilder.Build(request, parameters);

        Assert.StartsWith(
            "\"x-empty\";bs: :dmFsdWUsIHdpdGgsIGxvdHMsIG9mLCBjb21tYXM=:, :YW5vdGhlciB2YWx1ZQ==:\n",
            actual,
            StringComparison.Ordinal);
    }

    [Fact]
    public void ReqFlag_TakesComponentFromAssociatedRequest()
    {
        var response = Rfc9421TestVectors.TestResponse();
        var parameters = new SignatureParameters()
            .AddComponent(SignatureComponent.Status)
            .AddComponent(SignatureComponent.Method.WithRequest())
            .AddComponent(SignatureComponent.Field("content-digest").WithRequest());

        var actual = SignatureBaseBuilder.Build(response, parameters);

        Assert.Equal(
            "\"@status\": 200\n" +
            "\"@method\";req: POST\n" +
            $"\"content-digest\";req: {Rfc9421TestVectors.RequestContentDigest}\n" +
            "\"@signature-params\": (\"@status\" \"@method\";req \"content-digest\";req)",
            actual);
    }
}
