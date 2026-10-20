using System.Diagnostics;

namespace Qertum.Tests.Crypto;

/// <summary>Locates and runs an OpenSSL 3 binary for interoperability tests, which skip without one.</summary>
internal static class OpenSslTool
{
    /// <summary>An OpenSSL 3 binary: <c>QERTUM_OPENSSL</c>, Homebrew's, or the one on PATH, if it is version 3.</summary>
    public static string? Find()
    {
        string?[] candidates =
        [
            Environment.GetEnvironmentVariable("QERTUM_OPENSSL"),
            "/opt/homebrew/opt/openssl@3/bin/openssl",
            "/usr/local/opt/openssl@3/bin/openssl",
            "openssl"
        ];
        foreach (var candidate in candidates.OfType<string>())
        {
            try
            {
                var (exitCode, output) = Run(candidate, "version");
                if (exitCode == 0 && output.StartsWith("OpenSSL 3", StringComparison.Ordinal))
                    return candidate;
            }
            catch (System.ComponentModel.Win32Exception)
            {
                // Not installed at this path.
            }
        }

        return null;
    }

    /// <summary>True when the binary at <paramref name="openSsl"/> reports at least version <paramref name="major"/>.<paramref name="minor"/>.</summary>
    public static bool IsAtLeast(string openSsl, int major, int minor)
    {
        var (exitCode, output) = Run(openSsl, "version");
        var match = System.Text.RegularExpressions.Regex.Match(output, @"^OpenSSL (\d+)\.(\d+)");
        return exitCode == 0 && match.Success
            && (int.Parse(match.Groups[1].Value), int.Parse(match.Groups[2].Value)).CompareTo((major, minor)) >= 0;
    }

    public static (int ExitCode, string Output) Run(string fileName, string arguments)
    {
        // stdin must be a pipe: the test host sometimes hands children a socket, and OpenSSL's console
        // setup fails on a socket (tcgetattr errno 102) even when -passin supplies the passphrase.
        using var process = Process.Start(new ProcessStartInfo(fileName, arguments)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        })!;
        process.StandardInput.Close();
        var output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
        process.WaitForExit();
        return (process.ExitCode, output);
    }
}
