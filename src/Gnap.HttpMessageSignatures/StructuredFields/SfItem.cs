using System.Collections;
using System.Text;

namespace Gnap.HttpMessageSignatures.StructuredFields;

/// <summary>An ordered set of RFC 8941 parameters (lowercase keys with bare item values).</summary>
public sealed class SfParameters : IReadOnlyList<KeyValuePair<string, SfValue>>
{
    /// <summary>An empty, immutable parameter set.</summary>
    public static readonly SfParameters Empty = new();

    private readonly List<KeyValuePair<string, SfValue>> _entries = [];

    /// <summary>Creates an empty parameter set.</summary>
    public SfParameters()
    {
    }

    /// <summary>Creates a parameter set with the given entries, in order.</summary>
    public SfParameters(IEnumerable<KeyValuePair<string, SfValue>> entries)
    {
        foreach (var (key, value) in entries)
        {
            Add(key, value);
        }
    }

    /// <inheritdoc />
    public int Count => _entries.Count;

    /// <inheritdoc />
    public KeyValuePair<string, SfValue> this[int index] => _entries[index];

    /// <summary>Adds a parameter, replacing an existing entry with the same key in place.</summary>
    /// <exception cref="ArgumentException">The key is not a valid RFC 8941 key.</exception>
    public void Add(string key, SfValue value)
    {
        ValidateKey(key);
        for (var i = 0; i < _entries.Count; i++)
        {
            if (_entries[i].Key == key)
            {
                _entries[i] = new(key, value);
                return;
            }
        }

        _entries.Add(new(key, value));
    }

    /// <summary>Returns the value for <paramref name="key"/>, or <see langword="null"/> if absent.</summary>
    public SfValue? Get(string key)
    {
        foreach (var (k, v) in _entries)
        {
            if (k == key)
            {
                return v;
            }
        }

        return null;
    }

    /// <summary>Whether a parameter with the given key exists.</summary>
    public bool Contains(string key) => Get(key) is not null;

    internal static void ValidateKey(string key)
    {
        if (key.Length == 0 || !(char.IsAsciiLetterLower(key[0]) || key[0] == '*'))
        {
            throw new ArgumentException($"Invalid structured field key '{key}': must start with a lowercase letter or '*'.", nameof(key));
        }

        for (var i = 1; i < key.Length; i++)
        {
            if (!IsKeyChar(key[i]))
            {
                throw new ArgumentException($"Invalid structured field key '{key}': character '{key[i]}' is not allowed.", nameof(key));
            }
        }
    }

    internal static bool IsKeyChar(char c) =>
        char.IsAsciiLetterLower(c) || char.IsAsciiDigit(c) || c is '_' or '-' or '.' or '*';

    internal void SerializeTo(StringBuilder output)
    {
        foreach (var (key, value) in _entries)
        {
            output.Append(';').Append(key);
            if (value is not SfBoolean { Value: true })
            {
                output.Append('=');
                value.SerializeTo(output);
            }
        }
    }

    /// <inheritdoc />
    public IEnumerator<KeyValuePair<string, SfValue>> GetEnumerator() => _entries.GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}

/// <summary>A member of an RFC 8941 list or dictionary: either an item or an inner list.</summary>
public abstract class SfMember
{
    private protected SfMember(SfParameters parameters) => Parameters = parameters;

    /// <summary>The parameters attached to this member.</summary>
    public SfParameters Parameters { get; }

    internal abstract void SerializeTo(StringBuilder output);

    /// <summary>Returns the canonical RFC 8941 serialization of this member.</summary>
    public sealed override string ToString()
    {
        var sb = new StringBuilder();
        SerializeTo(sb);
        return sb.ToString();
    }
}

/// <summary>An RFC 8941 item: a bare value with parameters.</summary>
public sealed class SfItem : SfMember
{
    /// <summary>Creates an item from a bare value and optional parameters.</summary>
    public SfItem(SfValue value, SfParameters? parameters = null)
        : base(parameters ?? new SfParameters())
    {
        Value = value;
    }

    /// <summary>The bare item value.</summary>
    public SfValue Value { get; }

    internal override void SerializeTo(StringBuilder output)
    {
        Value.SerializeTo(output);
        Parameters.SerializeTo(output);
    }
}

/// <summary>An RFC 8941 inner list: parenthesized items with parameters.</summary>
public sealed class SfInnerList : SfMember
{
    /// <summary>Creates an inner list from items and optional parameters.</summary>
    public SfInnerList(IEnumerable<SfItem> items, SfParameters? parameters = null)
        : base(parameters ?? new SfParameters())
    {
        Items = items.ToArray();
    }

    /// <summary>The items of the inner list, in order.</summary>
    public IReadOnlyList<SfItem> Items { get; }

    internal override void SerializeTo(StringBuilder output)
    {
        output.Append('(');
        for (var i = 0; i < Items.Count; i++)
        {
            if (i > 0)
            {
                output.Append(' ');
            }

            Items[i].SerializeTo(output);
        }

        output.Append(')');
        Parameters.SerializeTo(output);
    }
}

/// <summary>An RFC 8941 dictionary: ordered lowercase keys mapping to members.</summary>
public sealed class SfDictionary : IReadOnlyList<KeyValuePair<string, SfMember>>
{
    private readonly List<KeyValuePair<string, SfMember>> _entries = [];

    /// <inheritdoc />
    public int Count => _entries.Count;

    /// <inheritdoc />
    public KeyValuePair<string, SfMember> this[int index] => _entries[index];

    /// <summary>Adds a member, replacing an existing entry with the same key in place.</summary>
    public void Add(string key, SfMember member)
    {
        SfParameters.ValidateKey(key);
        for (var i = 0; i < _entries.Count; i++)
        {
            if (_entries[i].Key == key)
            {
                _entries[i] = new(key, member);
                return;
            }
        }

        _entries.Add(new(key, member));
    }

    /// <summary>Returns the member for <paramref name="key"/>, or <see langword="null"/> if absent.</summary>
    public SfMember? Get(string key)
    {
        foreach (var (k, v) in _entries)
        {
            if (k == key)
            {
                return v;
            }
        }

        return null;
    }

    /// <summary>Returns the canonical RFC 8941 serialization of this dictionary.</summary>
    public override string ToString()
    {
        var sb = new StringBuilder();
        for (var i = 0; i < _entries.Count; i++)
        {
            if (i > 0)
            {
                sb.Append(", ");
            }

            var (key, member) = _entries[i];
            if (member is SfItem { Value: SfBoolean { Value: true } } item)
            {
                sb.Append(key);
                item.Parameters.SerializeTo(sb);
            }
            else
            {
                sb.Append(key).Append('=');
                member.SerializeTo(sb);
            }
        }

        return sb.ToString();
    }

    /// <inheritdoc />
    public IEnumerator<KeyValuePair<string, SfMember>> GetEnumerator() => _entries.GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}

/// <summary>An RFC 8941 list of items and inner lists.</summary>
public sealed class SfList : IReadOnlyList<SfMember>
{
    private readonly List<SfMember> _members = [];

    /// <inheritdoc />
    public int Count => _members.Count;

    /// <inheritdoc />
    public SfMember this[int index] => _members[index];

    /// <summary>Appends a member to the list.</summary>
    public void Add(SfMember member) => _members.Add(member);

    /// <summary>Returns the canonical RFC 8941 serialization of this list.</summary>
    public override string ToString()
    {
        var sb = new StringBuilder();
        for (var i = 0; i < _members.Count; i++)
        {
            if (i > 0)
            {
                sb.Append(", ");
            }

            _members[i].SerializeTo(sb);
        }

        return sb.ToString();
    }

    /// <inheritdoc />
    public IEnumerator<SfMember> GetEnumerator() => _members.GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}
