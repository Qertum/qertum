namespace Qertum.Tests.Deploy;

/// <summary>
/// The single container's half of the forwarded-headers rule (see
/// <see cref="MultiContainerContractTests.ForwardedHeaders_AreTrustedOnlyByTheProxiedServices_InHttpsMode"/>):
/// on with QERTUM_PUBLIC_SCHEME=https for the services behind the proxy, never for ACME.
/// </summary>
public sealed class SingleContainerForwardedHeadersTests
{
    [Theory]
    [InlineData("https", "true")]
    [InlineData("http", "unset")]
    public void Entrypoint_TrustsForwardedHeadersOnlyInHttpsMode(string scheme, string expected)
    {
        var entrypoint = Read("entrypoint.sh");
        const string opening = "if [ \"${QERTUM_PUBLIC_SCHEME}\" = \"https\" ]; then\n  export ASPNETCORE_FORWARDEDHEADERS_ENABLED";
        var start = entrypoint.IndexOf(opening, StringComparison.Ordinal);
        Assert.True(start >= 0, "the forwarded-headers block is missing");
        var block = entrypoint[start..(entrypoint.IndexOf("\nfi", start, StringComparison.Ordinal) + 3)];

        var result = MultiContainerContractTests.RunSh(
            $"QERTUM_PUBLIC_SCHEME={scheme}\n{block}\nprintf %s \"${{ASPNETCORE_FORWARDEDHEADERS_ENABLED-unset}}\"");

        Assert.Equal(expected, result);
    }

    [Fact]
    public void AcmeService_NeverTrustsForwardedHeaders()
    {
        // The entrypoint exports the variable for every runit service; ACME's run script removes it again.
        var run = Read(Path.Combine("service", "acmeservice", "run"));
        var commands = run.Split('\n').Where(line => !line.TrimStart().StartsWith('#')).ToList();
        var unset = commands.FindIndex(line => line.Trim() == "unset ASPNETCORE_FORWARDEDHEADERS_ENABLED");
        var exec = commands.FindIndex(line => line.TrimStart().StartsWith("exec dotnet", StringComparison.Ordinal));

        Assert.True(unset >= 0 && unset < exec, "acmeservice/run must unset ASPNETCORE_FORWARDEDHEADERS_ENABLED before it starts");
    }

    private static string Read(string name)
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            var path = Path.Combine(dir.FullName, "deploy", "single-container", name);
            if (File.Exists(path))
                return File.ReadAllText(path);
        }

        throw new FileNotFoundException(name);
    }
}
