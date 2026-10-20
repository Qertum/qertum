using System.Diagnostics;

namespace Qertum.Tests.Recovery;

/// <summary>
/// The string checks in <see cref="RecoveryScriptContractTests"/> cannot tell a script that works from one that does not parse
/// or binds its parameters wrongly. These tests run the real <c>.ps1</c> files with <c>pwsh</c>, and are skipped where
/// PowerShell 7 is not installed. They need no Docker: they stop at the first check that fails before Docker is used.
/// </summary>
public sealed class PowerShellScriptRunTests
{
    private static string? FindPwsh()
    {
        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? string.Empty).Split(Path.PathSeparator))
        {
            foreach (var name in new[] { "pwsh", "pwsh.exe" })
            {
                var candidate = Path.Combine(dir, name);
                if (File.Exists(candidate))
                    return candidate;
            }
        }

        return null;
    }

    private static string RepoFile(params string[] relative)
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            var path = Path.Combine([dir.FullName, .. relative]);
            if (File.Exists(path))
                return path;
        }

        throw new FileNotFoundException(Path.Combine(relative));
    }

    private static async Task<(int ExitCode, string Output)> RunAsync(string pwsh, params string[] arguments)
    {
        var info = new ProcessStartInfo(pwsh) { RedirectStandardOutput = true, RedirectStandardError = true };
        info.ArgumentList.Add("-NoProfile");
        foreach (var argument in arguments)
            info.ArgumentList.Add(argument);

        using var process = Process.Start(info)!;
        var output = await process.StandardOutput.ReadToEndAsync(TestContext.Current.CancellationToken);
        output += await process.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);
        await process.WaitForExitAsync(TestContext.Current.CancellationToken);
        return (process.ExitCode, output);
    }

    public static TheoryData<string> Scripts() => new()
    {
        "deploy/single-container/backup.ps1", "deploy/single-container/restore.ps1", "deploy/single-container/restore-test.ps1",
        "deploy/multi-container/backup.ps1", "deploy/multi-container/restore.ps1", "deploy/multi-container/restore-test.ps1"
    };

    [Theory]
    [MemberData(nameof(Scripts))]
    public async Task EveryScript_Parses(string relative)
    {
        var pwsh = FindPwsh();
        Assert.SkipWhen(pwsh is null, "PowerShell 7 (pwsh) is not installed.");
        var path = RepoFile(relative.Split('/'));

        var (code, output) = await RunAsync(pwsh!, "-Command",
            $"$e = $null; $t = $null; [System.Management.Automation.Language.Parser]::ParseFile('{path.Replace("'", "''")}', [ref]$t, [ref]$e) | Out-Null; " +
            "$e | ForEach-Object { 'line ' + $_.Extent.StartLineNumber + ': ' + $_.Message }; exit [int]($e.Count -gt 0)");

        Assert.True(code == 0, $"{relative} does not parse:{Environment.NewLine}{output}");
    }

    [Fact]
    public async Task TheMultiContainerRestoreTestWrapper_PassesImageOnAsANamedParameter_AndFailsLoudly()
    {
        // Splatting an array passes '-Image' as a positional value ("A positional parameter cannot be found ..."), and a
        // binding error leaves $LASTEXITCODE unset, so the wrapper exited 0. A target that does not exist must be exit 2
        // (or exit 2 for an unreachable Docker): never 0, and never a binding error.
        var pwsh = FindPwsh();
        Assert.SkipWhen(pwsh is null, "PowerShell 7 (pwsh) is not installed.");
        var script = RepoFile("deploy", "multi-container", "restore-test.ps1");

        var (code, output) = await RunAsync(pwsh!, "-File", script, "-Target", "/no/such/target", "-Image", "example:none");

        Assert.DoesNotContain("positional parameter", output);
        Assert.Equal(2, code);
    }
}
