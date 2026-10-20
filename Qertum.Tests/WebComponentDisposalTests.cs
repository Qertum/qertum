using System.Text.RegularExpressions;

namespace Qertum.Tests;

/// <summary>
/// Blazor calls <c>Dispose</c> only on a component that declares <c>@implements IDisposable</c>
/// (or <c>IAsyncDisposable</c>); a public <c>Dispose()</c> method alone is never invoked. A
/// component that starts a timer without the declaration leaks it on every render of the page —
/// prerender included — and each leaked timer keeps calling the API for the life of the circuit.
/// That is how the dashboard's 5-second summary poll multiplied until the API's shared rate limit
/// answered 429 and the Web client's circuit breaker refused every call.
/// </summary>
public sealed class WebComponentDisposalTests
{
    // A CancellationTokenSource guards async work that must stop with the component (the request
    // wizard's policy preview), so it needs the same declaration a timer does.
    private static readonly Regex StartsTimer = new(
        @"new\s+(System\.Threading\.)?Timer\s*\(|new\s+PeriodicTimer\s*\(|new\s+(System\.Threading\.)?CancellationTokenSource\s*\(");
    private static readonly Regex DeclaresDisposal = new(@"^@implements\s+(System\.)?I(Async)?Disposable\b", RegexOptions.Multiline);

    [Fact]
    public void EveryComponentThatStartsATimerOrCancellableWorkDeclaresDisposal()
    {
        var componentsDir = Path.Combine(FindRepoRoot(), "Qertum.Web", "Components");
        var razorFiles = Directory.GetFiles(componentsDir, "*.razor", SearchOption.AllDirectories);
        Assert.NotEmpty(razorFiles);

        var offenders = razorFiles
            .Where(path =>
            {
                var source = File.ReadAllText(path);
                return StartsTimer.IsMatch(source) && !DeclaresDisposal.IsMatch(source);
            })
            .Select(path => Path.GetRelativePath(componentsDir, path))
            .ToList();

        Assert.Empty(offenders);
    }

    private static string FindRepoRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            if (File.Exists(Path.Combine(dir.FullName, "Qertum.sln")))
                return dir.FullName;
        }

        throw new InvalidOperationException("Could not locate Qertum.sln above " + AppContext.BaseDirectory);
    }
}
