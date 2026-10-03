using System.Diagnostics;

namespace Gnap.Client.Interaction;

/// <summary>Opens interaction URIs in the user's default browser (console and desktop apps).</summary>
public static class SystemBrowser
{
    /// <summary>
    /// Opens an <c>https</c> (or <c>http</c>) URI with the operating system's default
    /// handler. Other schemes are refused so an AS cannot launch arbitrary programs.
    /// </summary>
    /// <exception cref="ArgumentException">The URI is not an absolute http(s) URI.</exception>
    public static void Open(Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);
        if (!uri.IsAbsoluteUri || uri.Scheme is not ("https" or "http"))
        {
            throw new ArgumentException("Only absolute http(s) URIs are opened in the browser.", nameof(uri));
        }

        using var process = Process.Start(new ProcessStartInfo(uri.AbsoluteUri) { UseShellExecute = true });
    }
}
