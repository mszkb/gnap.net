namespace Gnap.Interop.Tests;

/// <summary>
/// A fact that only runs when the environment variable naming its peer
/// implementation is set (e.g. <c>GNAP_INTEROP_RAFIKI</c>); otherwise it is
/// reported as skipped, so <c>dotnet test Gnap.sln</c> stays hermetic.
/// </summary>
[AttributeUsage(AttributeTargets.Method)]
public sealed class InteropFactAttribute : FactAttribute
{
    public InteropFactAttribute(string environmentVariable)
    {
        if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable(environmentVariable)))
        {
            Skip = $"Interop peer not configured: set {environmentVariable} (see docs/interop.md).";
        }
    }
}

/// <summary>The theory counterpart of <see cref="InteropFactAttribute"/>.</summary>
[AttributeUsage(AttributeTargets.Method)]
public sealed class InteropTheoryAttribute : TheoryAttribute
{
    public InteropTheoryAttribute(string environmentVariable)
    {
        if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable(environmentVariable)))
        {
            Skip = $"Interop peer not configured: set {environmentVariable} (see docs/interop.md).";
        }
    }
}

/// <summary>Reads interop settings from the environment.</summary>
internal static class InteropEnvironment
{
    public static string Get(string name, string fallback) =>
        Environment.GetEnvironmentVariable(name) is { Length: > 0 } value ? value : fallback;

    /// <summary>The repository root (the directory containing Gnap.sln).</summary>
    public static string RepositoryRoot
    {
        get
        {
            var directory = new DirectoryInfo(AppContext.BaseDirectory);
            while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Gnap.sln")))
            {
                directory = directory.Parent;
            }

            return directory?.FullName ?? throw new InvalidOperationException("Gnap.sln not found above the test binaries.");
        }
    }
}
