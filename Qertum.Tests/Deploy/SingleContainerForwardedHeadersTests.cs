namespace Qertum.Tests.Deploy;

/// <summary>
/// The single container's half of the forwarded-headers rule (see
/// <see cref="MultiContainerContractTests.ForwardedHeaders_AreTrustedOnlyByTheProxiedServices_InHttpsMode"/>):
/// on with QERTUM_PUBLIC_SCHEME=https for the services behind the proxy, from QERTUM_TRUSTED_PROXIES only
/// (required), never for ACME.
/// </summary>
public sealed class SingleContainerForwardedHeadersTests
{
    [Theory]
    [InlineData("https", "true|172.18.0.0/16")]
    [InlineData("http", "unset|unset")]
    public void Entrypoint_TrustsForwardedHeadersOnlyInHttpsMode_FromTheNamedProxies(string scheme, string expected)
    {
        var result = MultiContainerContractTests.RunSh(
            $"QERTUM_PUBLIC_SCHEME={scheme}\nQERTUM_TRUSTED_PROXIES=172.18.0.0/16\n{ForwardedHeadersBlock()}\n" +
            "printf %s \"${ASPNETCORE_FORWARDEDHEADERS_ENABLED-unset}|${ForwardedHeaders__TrustedProxies-unset}\"");

        Assert.Equal(expected, result);
    }

    [Fact]
    public void HttpsMode_RefusesToStartWithoutATrustedProxy() =>
        MultiContainerContractTests.RunSh($"QERTUM_PUBLIC_SCHEME=https\n{ForwardedHeadersBlock()}", expectedExit: 64);

    private static string ForwardedHeadersBlock()
    {
        var entrypoint = Read("entrypoint.sh");
        const string opening = "if [ \"${QERTUM_PUBLIC_SCHEME}\" = \"https\" ]; then\n  if [ -z \"${QERTUM_TRUSTED_PROXIES:-}\" ]";
        var start = entrypoint.IndexOf(opening, StringComparison.Ordinal);
        Assert.True(start >= 0, "the forwarded-headers block is missing");
        return entrypoint[start..(entrypoint.IndexOf("\nfi", start, StringComparison.Ordinal) + 3)];
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
