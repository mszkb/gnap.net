using FsCheck;
using FsCheck.Fluent;
using Gnap.HttpMessageSignatures.StructuredFields;
using Xunit;

namespace Gnap.HttpMessageSignatures.Tests;

/// <summary>
/// Property-based tests (FsCheck) showing that signature base construction is
/// deterministic and robust for arbitrary header and query combinations, that
/// sign→verify roundtrips for every algorithm, and that the structured field and
/// <c>@query-param</c> codecs are stable.
/// </summary>
public class PropertyBasedTests
{
    private const int CryptoMaxTest = 30;

    private static readonly string[] AlgorithmNames =
    [
        "rsa-pss-sha512",
        "rsa-v1_5-sha256",
        "ecdsa-p256-sha256",
        "ecdsa-p384-sha384",
        "hmac-sha256",
        "ed25519",
    ];

    // Key generation (RSA in particular) is expensive, so one key per algorithm is
    // shared by all generated cases.
    private static readonly Dictionary<string, SignatureAlgorithm> Keys =
        AlgorithmNames.ToDictionary(n => n, RoundtripTests.CreateFreshKey);

    // ---------------------------------------------------------------------
    // Signature base: determinism, header ordering and casing
    // ---------------------------------------------------------------------

    [Fact]
    public void SignatureBase_IsDeterministic()
    {
        Prop.ForAll(Generators.Scenario.ToArbitrary(), scenario =>
        {
            var parameters = scenario.Parameters();
            var first = SignatureBaseBuilder.Build(scenario.ToMessage(), parameters);
            var again = SignatureBaseBuilder.Build(scenario.ToMessage(), parameters);
            var sameInstance = scenario.ToMessage();
            return first == again
                && SignatureBaseBuilder.Build(sameInstance, parameters) == SignatureBaseBuilder.Build(sameInstance, parameters);
        }).QuickCheckThrowOnFailure();
    }

    [Fact]
    public void SignatureBase_IgnoresHeaderOrderAndFieldNameCasing()
    {
        var gen =
            from scenario in Generators.Scenario
            from shuffled in Gen.Shuffle(scenario.AllHeaders())
            from recased in Gen.CollectToSequence(shuffled, h => Generators.RandomCasing(h.Name).Select(n => (n, h.Value)))
            select (scenario, recased.ToArray());

        Prop.ForAll(gen.ToArbitrary(), t =>
        {
            var (scenario, reordered) = t;
            var original = SignatureBaseBuilder.Build(scenario.ToMessage(), scenario.Parameters());
            var transformed = SignatureBaseBuilder.Build(scenario.ToMessage(reordered), scenario.Parameters());
            return original == transformed;
        }).QuickCheckThrowOnFailure();
    }

    [Fact]
    public void SignatureBase_ContainsOneLinePerCoveredComponentPlusParams()
    {
        Prop.ForAll(Generators.Scenario.ToArbitrary(), scenario =>
        {
            var parameters = scenario.Parameters();
            var lines = SignatureBaseBuilder.Build(scenario.ToMessage(), parameters).Split('\n');
            return lines.Length == parameters.Components.Count + 1
                && lines[^1].StartsWith("\"@signature-params\": ", StringComparison.Ordinal);
        }).QuickCheckThrowOnFailure();
    }

    // ---------------------------------------------------------------------
    // Sign → verify roundtrip and sensitivity
    // ---------------------------------------------------------------------

    [Fact]
    public void SignThenVerify_SucceedsForAllAlgorithms()
    {
        var gen = Gen.Zip(Gen.Elements(AlgorithmNames), Generators.Scenario);
        Prop.ForAll(gen.Resize(20).ToArbitrary(), t =>
        {
            var (algorithmName, scenario) = t;
            var message = scenario.ToMessage();
            AttachSignature(message, Sign(algorithmName, scenario, message));
            var result = Verify(algorithmName, message);
            return result.Succeeded.Label($"{algorithmName}: {result.FailureReason}");
        }).Check(Config.QuickThrowOnFailure.WithMaxTest(CryptoMaxTest * AlgorithmNames.Length));
    }

    [Fact]
    public void ModifiedCoveredComponent_FailsVerification()
    {
        var gen =
            from algorithmName in Gen.Elements(AlgorithmNames)
            from scenario in Generators.Scenario
            from target in Gen.Choose(0, scenario.Covered.Length + scenario.QueryParams.Length - 1)
            select (algorithmName, scenario, target);

        Prop.ForAll(gen.Resize(20).ToArbitrary(), t =>
        {
            var (algorithmName, scenario, target) = t;
            var signed = Sign(algorithmName, scenario, scenario.ToMessage());

            // Tamper with exactly one covered header value or covered query parameter value.
            var tampered = target < scenario.Covered.Length
                ? scenario with { Covered = scenario.Covered.Select((h, i) => i == target ? (h.Name, h.Value + "x") : h).ToArray() }
                : scenario with
                {
                    QueryParams = scenario.QueryParams
                        .Select((q, i) => i == target - scenario.Covered.Length ? (q.Name, q.Value + "x") : q)
                        .ToArray(),
                };

            var message = tampered.ToMessage();
            AttachSignature(message, signed);
            var result = Verify(algorithmName, message);
            return (!result.Succeeded).Label($"{algorithmName}: tampered message verified");
        }).Check(Config.QuickThrowOnFailure.WithMaxTest(CryptoMaxTest * AlgorithmNames.Length));
    }

    private static SigningResult Sign(string algorithmName, Generators.MessageScenario scenario, IHttpMessageContext message) =>
        new HttpMessageSigner(Keys[algorithmName])
        {
            KeyId = algorithmName,
            CoveredComponents = scenario.Parameters().Components,
        }.Sign(message);

    private static void AttachSignature(SimpleHttpMessage message, SigningResult signed)
    {
        message.WithHeader("Signature-Input", signed.SignatureInput);
        message.WithHeader("Signature", signed.Signature);
    }

    private static VerificationResult Verify(string algorithmName, IHttpMessageContext message)
    {
        var verifier = new HttpMessageVerifier(new VerificationOptions
        {
            KeyResolver = new StaticKeyResolver().Add(algorithmName, Keys[algorithmName]),
        });
        return verifier.VerifyAsync(message).GetAwaiter().GetResult();
    }

    // ---------------------------------------------------------------------
    // Structured fields (RFC 8941)
    // ---------------------------------------------------------------------

    [Fact]
    public void StructuredDictionary_SerializeParseSerialize_IsStable()
    {
        Prop.ForAll(Generators.SfDictionary.ToArbitrary(), dictionary =>
        {
            var serialized = dictionary.ToString();
            var reparsed = SfParser.ParseDictionary(serialized).ToString();
            return (reparsed == serialized).Label($"{serialized} -> {reparsed}");
        }).QuickCheckThrowOnFailure();
    }

    [Fact]
    public void StructuredList_SerializeParseSerialize_IsStable()
    {
        Prop.ForAll(Generators.SfList.ToArbitrary(), list =>
        {
            var serialized = list.ToString();
            var reparsed = SfParser.ParseList(serialized).ToString();
            return (reparsed == serialized).Label($"{serialized} -> {reparsed}");
        }).QuickCheckThrowOnFailure();
    }

    [Fact]
    public void StructuredItem_SerializeParseSerialize_IsStable()
    {
        Prop.ForAll(Generators.SfItem.ToArbitrary(), item =>
        {
            var serialized = item.ToString();
            var reparsed = SfParser.ParseItem(serialized).ToString();
            return (reparsed == serialized).Label($"{serialized} -> {reparsed}");
        }).QuickCheckThrowOnFailure();
    }

    [Fact]
    public void StructuredDictionary_ParseIsIdempotentUnderWhitespace()
    {
        // Parse → serialize → parse yields the same canonical form even when the
        // input uses the optional whitespace RFC 8941 permits around members.
        var gen =
            from dictionary in Generators.SfDictionary
            from leading in Gen.Elements("", " ", "   ")
            from separator in Gen.Elements(", ", ",", " ,\t", ",  ")
            select (dictionary, leading + string.Join(separator, dictionary.Select(Generators.SerializeDictionaryMember)));

        Prop.ForAll(gen.ToArbitrary(), t =>
        {
            var (dictionary, loose) = t;
            var canonical = SfParser.ParseDictionary(loose).ToString();
            return canonical == dictionary.ToString()
                && SfParser.ParseDictionary(canonical).ToString() == canonical;
        }).QuickCheckThrowOnFailure();
    }

    // ---------------------------------------------------------------------
    // @query-param codec
    // ---------------------------------------------------------------------

    [Fact]
    public void QueryCodec_DecodeOfEncode_IsIdentity()
    {
        Prop.ForAll(Generators.UnicodeText.ToArbitrary(), text =>
            QueryParameterCodec.Decode(QueryParameterCodec.Encode(text)) == text)
            .QuickCheckThrowOnFailure();
    }

    [Fact]
    public void QueryCodec_Encode_ProducesOnlyUnreservedCharactersAndUppercaseEscapes()
    {
        Prop.ForAll(Generators.UnicodeText.ToArbitrary(), text =>
        {
            var encoded = QueryParameterCodec.Encode(text);
            for (var i = 0; i < encoded.Length; i++)
            {
                var c = encoded[i];
                if (c == '%')
                {
                    if (i + 2 >= encoded.Length || !IsUpperHex(encoded[i + 1]) || !IsUpperHex(encoded[i + 2]))
                    {
                        return false;
                    }

                    i += 2;
                }
                else if (!(char.IsAsciiLetterOrDigit(c) || c is '-' or '.' or '_' or '~'))
                {
                    return false;
                }
            }

            return true;
        }).QuickCheckThrowOnFailure();

        static bool IsUpperHex(char c) => char.IsAsciiDigit(c) || c is >= 'A' and <= 'F';
    }

    [Fact]
    public void QueryCodec_ParseOfSerializedQuery_RoundtripsPairsInOrder()
    {
        var pair = Gen.Zip(Generators.UnicodeText, Generators.UnicodeText);
        Prop.ForAll(pair.ListOf().ToArbitrary(), pairs =>
        {
            var raw = string.Join("&", pairs.Select(p => $"{FormEncode(p.Item1)}={FormEncode(p.Item2)}"));
            var parsed = QueryParameterCodec.Parse(raw).ToArray();
            return parsed.SequenceEqual(pairs.Select(p => (p.Item1, p.Item2)));
        }).QuickCheckThrowOnFailure();

        // Lenient form encoding as browsers produce it: spaces become '+'.
        static string FormEncode(string s) => Uri.EscapeDataString(s).Replace("%20", "+", StringComparison.Ordinal);
    }

    [Fact]
    public void QueryParamComponent_ResolvesEncodedValueFromAnyTargetUri()
    {
        var gen =
            from name in Generators.UnicodeText.Where(s => s.Length > 0)
            from value in Generators.UnicodeText
            select (name, value);

        Prop.ForAll(gen.ToArbitrary(), t =>
        {
            var (name, value) = t;
            var uri = $"https://example.com/p?{Uri.EscapeDataString(name)}={Uri.EscapeDataString(value)}";
            var component = SignatureComponent.QueryParam(name);
            var signatureBase = SignatureBaseBuilder.Build(
                SimpleHttpMessage.Request("GET", uri),
                new SignatureParameters().AddComponent(component));
            var expectedLine = $"{component}: {QueryParameterCodec.Encode(value)}\n";
            return signatureBase.StartsWith(expectedLine, StringComparison.Ordinal);
        }).QuickCheckThrowOnFailure();
    }

    /// <summary>Generators for messages, structured fields and query text.</summary>
    internal static class Generators
    {
        private const string Lower = "abcdefghijklmnopqrstuvwxyz";
        private const string Digits = "0123456789";

        /// <summary>A request with covered and uncovered headers plus covered query parameters.</summary>
        internal sealed record MessageScenario(
            string Method,
            string Path,
            (string Name, string Value)[] Covered,
            (string Name, string Value)[] Uncovered,
            (string Name, string Value)[] QueryParams)
        {
            public string TargetUri
            {
                get
                {
                    var query = string.Join("&", QueryParams.Select(q => $"{Uri.EscapeDataString(q.Name)}={Uri.EscapeDataString(q.Value)}"));
                    return $"https://example.com{Path}{(query.Length > 0 ? "?" + query : string.Empty)}";
                }
            }

            public IEnumerable<(string Name, string Value)> AllHeaders() => Covered.Concat(Uncovered);

            public SimpleHttpMessage ToMessage() => ToMessage(AllHeaders());

            public SimpleHttpMessage ToMessage(IEnumerable<(string Name, string Value)> headers)
            {
                var message = SimpleHttpMessage.Request(Method, TargetUri);
                foreach (var (name, value) in headers)
                {
                    message.WithHeader(name, value);
                }

                return message;
            }

            public SignatureParameters Parameters() => new SignatureParameters()
                .AddComponent(SignatureComponent.Method)
                .AddComponent(SignatureComponent.TargetUri)
                .AddComponent(SignatureComponent.Authority)
                .AddComponent(SignatureComponent.Path)
                .AddComponent(SignatureComponent.Query)
                .AddComponents(Covered.Select(h => SignatureComponent.Field(h.Name)))
                .AddComponents(QueryParams.Select(q => SignatureComponent.QueryParam(q.Name)))
                .WithCreated(DateTimeOffset.FromUnixTimeSeconds(1_700_000_000))
                .WithKeyId("test-key");
        }

        public static Gen<string> Chars(string alphabet, int min, int max) =>
            from length in Gen.Choose(min, max)
            from chars in Gen.Elements(alphabet.ToCharArray()).ArrayOf(length)
            select new string(chars);

        /// <summary>Lowercase field names, prefixed to avoid clashing with real headers.</summary>
        public static Gen<string> FieldName =>
            from first in Gen.Elements(Lower.ToCharArray())
            from rest in Chars(Lower + Digits + "-", 0, 10)
            select $"x-{first}{rest}";

        /// <summary>Visible ASCII with embedded spaces/tabs and optional surrounding whitespace.</summary>
        public static Gen<string> FieldValue =>
            from leading in Gen.Elements("", " ", "\t", "  ")
            from body in Chars(VisibleAscii + " \t", 0, 20)
            from last in Gen.Elements(VisibleAscii.ToCharArray())
            from trailing in Gen.Elements("", " ", "\t ")
            select leading + body + last + trailing;

        private static string VisibleAscii { get; } =
            new(Enumerable.Range(0x21, 0x7e - 0x21 + 1).Select(i => (char)i).ToArray());

        /// <summary>Strings mixing ASCII, reserved characters and multi-byte UTF-8 (valid UTF-16 only).</summary>
        public static Gen<string> UnicodeText =>
            from parts in Gen.Elements(
                "a", "Z", "0", "-", ".", "_", "~", " ", "+", "&", "=", "%", "?", "/", "#", "!", "*", "'", "\"",
                "ä", "ß", "€", "日本", "😀", " ").ListOf()
            select string.Concat(parts);

        public static Gen<string> RandomCasing(string name) =>
            from flags in Gen.Elements(true, false).ArrayOf(name.Length)
            select new string(name.Select((c, i) => flags[i] ? char.ToUpperInvariant(c) : c).ToArray());

        public static Gen<MessageScenario> Scenario =>
            from method in Gen.Elements("GET", "POST", "PUT", "DELETE", "PATCH")
            from path in Gen.Elements("/", "/foo", "/foo/bar", "/api/items/42")
            from covered in DistinctBy(Gen.Zip(FieldName, FieldValue), 1, 6)
            from uncovered in DistinctBy(Gen.Zip(FieldName, FieldValue), 0, 6)
            from query in DistinctBy(Gen.Zip(UnicodeText.Where(s => s.Length > 0), UnicodeText), 0, 4)
            select new MessageScenario(
                method,
                path,
                covered,
                uncovered.Where(u => covered.All(c => c.Item1 != u.Item1)).ToArray(),
                query);

        private static Gen<(string, string)[]> DistinctBy(Gen<(string, string)> pair, int min, int max) =>
            from count in Gen.Choose(min, max)
            from pairs in pair.ArrayOf(count)
            select pairs.DistinctBy(p => p.Item1).ToArray();

        // --- RFC 8941 -------------------------------------------------------

        public static Gen<string> Key =>
            from first in Gen.Elements((Lower + "*").ToCharArray())
            from rest in Chars(Lower + Digits + "_-.*", 0, 8)
            select first + rest;

        public static Gen<SfValue> BareItem => Gen.OneOf(
            Chars(VisibleAscii + " ", 0, 16).Select(s => (SfValue)new SfString(s)),
            (from first in Gen.Elements((Lower + Lower.ToUpperInvariant() + "*").ToCharArray())
             from rest in Chars(Lower + Digits + ":/!#$%&'*+-.^_`|~", 0, 10)
             select (SfValue)new SfToken(first + rest)),
            Gen.Choose(int.MinValue, int.MaxValue).Zip(Gen.Choose(0, 999_999), (hi, lo) => (long)hi * 1_000_000 + lo)
                .Select(v => (SfValue)new SfInteger(Math.Clamp(v, -SfInteger.Max, SfInteger.Max))),
            Gen.Choose(-999_999_999, 999_999_999).Zip(Gen.Choose(0, 999), (i, f) => (SfValue)new SfDecimal(i + (Math.Sign(i) < 0 ? -f : f) / 1000m)),
            Gen.Elements<SfValue>(SfBoolean.True, SfBoolean.False),
            Gen.Choose(0, 255).ArrayOf().Select(b => (SfValue)new SfBytes(b.Select(x => (byte)x).ToArray())));

        public static Gen<SfParameters> Parameters =>
            from count in Gen.Choose(0, 3)
            from entries in Gen.Zip(Key, BareItem).ArrayOf(count)
            select new SfParameters(entries.Select(e => new KeyValuePair<string, SfValue>(e.Item1, e.Item2)));

        public static Gen<SfItem> SfItem =>
            from value in BareItem
            from parameters in Parameters
            select new SfItem(value, parameters);

        public static Gen<SfMember> Member => Gen.OneOf(
            SfItem.Select(i => (SfMember)i),
            from count in Gen.Choose(0, 4)
            from items in SfItem.ArrayOf(count)
            from parameters in Parameters
            select (SfMember)new SfInnerList(items, parameters));

        public static Gen<SfDictionary> SfDictionary =>
            from count in Gen.Choose(1, 6)
            from entries in Gen.Zip(Key, Member).ArrayOf(count)
            select BuildDictionary(entries);

        public static Gen<SfList> SfList =>
            from count in Gen.Choose(1, 6)
            from members in Member.ArrayOf(count)
            select BuildList(members);

        public static string SerializeDictionaryMember(KeyValuePair<string, SfMember> entry)
        {
            var single = new StructuredFields.SfDictionary { { entry.Key, entry.Value } };
            return single.ToString();
        }

        private static StructuredFields.SfDictionary BuildDictionary(IEnumerable<(string Key, SfMember Member)> entries)
        {
            var dictionary = new StructuredFields.SfDictionary();
            foreach (var (key, member) in entries)
            {
                dictionary.Add(key, member);
            }

            return dictionary;
        }

        private static StructuredFields.SfList BuildList(IEnumerable<SfMember> members)
        {
            var list = new StructuredFields.SfList();
            foreach (var member in members)
            {
                list.Add(member);
            }

            return list;
        }
    }
}
