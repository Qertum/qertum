using System.Text.RegularExpressions;

namespace Qertum.Tests.Deploy;

/// <summary>
/// In the single container, <c>WEB_PORT</c>, <c>IDENTITY_PORT</c>, <c>API_PORT</c> and <c>ACME_PORT</c> are the
/// advertised (published) ports; every service listens on its fixed port from <c>service/&lt;name&gt;/run</c>. A URL
/// that one process uses to reach another inside the container must therefore name the fixed port. The web UI
/// used <c>http://localhost:${API_PORT}</c> and answered "Connection refused" whenever the API was published on
/// another host port (for example <c>-p 9082:8082 -e API_PORT=9082</c>).
/// </summary>
public sealed partial class SingleContainerPortContractTests
{
    [Fact]
    public void InContainerUrls_UseTheFixedListenPorts_NeverTheAdvertisedOnes()
    {
        var listening = ListenPorts();
        Assert.Contains("8082", listening);

        var internalUrls = Read("entrypoint.sh").Split('\n')
            .Where(line => !line.TrimStart().StartsWith('#'))
            .SelectMany(line => InternalUrl().Matches(line).Select(match => (Line: line.Trim(), Port: match.Groups["port"].Value)))
            .ToList();

        Assert.NotEmpty(internalUrls);
        var offenders = internalUrls
            .Where(url => url.Port.StartsWith('$') || !(listening.Contains(url.Port) || url.Port == "6379"))
            .Select(url => url.Line)
            .ToList();
        Assert.True(offenders.Count == 0,
            $"in-container URLs must use a fixed listen port ({string.Join(", ", listening)} or the cache's 6379): {string.Join("; ", offenders)}");
    }

    [Fact]
    public void TheWebUiReachesTheApiOnItsListenPort() =>
        Assert.Contains("export ApiService__BaseUrl=\"http://localhost:8082\"", Read("entrypoint.sh"), StringComparison.Ordinal);

    private static HashSet<string> ListenPorts()
    {
        var root = Path.GetDirectoryName(Locate("entrypoint.sh"))!;
        return Directory.GetDirectories(Path.Combine(root, "service"))
            .Select(dir => Path.Combine(dir, "run"))
            .Where(File.Exists)
            .SelectMany(run => ListenPort().Matches(File.ReadAllText(run)).Select(match => match.Groups["port"].Value))
            .ToHashSet();
    }

    private static string Read(string name) => File.ReadAllText(Locate(name));

    private static string Locate(string name)
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            var path = Path.Combine(dir.FullName, "deploy", "single-container", name);
            if (File.Exists(path))
                return path;
        }

        throw new FileNotFoundException(name);
    }

    [GeneratedRegex(@"https?://(?:localhost|127\.0\.0\.1):(?<port>\$\{?[A-Za-z_]+\}?|[0-9]+)")]
    private static partial Regex InternalUrl();

    [GeneratedRegex(@"ASPNETCORE_URLS=""https?://0\.0\.0\.0:(?<port>[0-9]+)""")]
    private static partial Regex ListenPort();
}
