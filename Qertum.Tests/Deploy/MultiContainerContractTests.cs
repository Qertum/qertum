using System.Text.RegularExpressions;

namespace Qertum.Tests.Deploy;

/// <summary>
/// The multi-container files are Dockerfile, shell and compose, so no unit test runs them. This pins
/// the layout that has to stay in step across them; the real check is the manual run in
/// deploy/multi-container/README.md.
/// </summary>
public sealed class MultiContainerContractTests
{
    private static readonly string[] Services =
        ["identityservice", "apiservice", "webfrontend", "acmeservice", "estservice", "queueconsumer"];

    internal static string Read(string name)
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            var path = Path.Combine(dir.FullName, "deploy", "multi-container", name);
            if (File.Exists(path))
                return File.ReadAllText(path);
        }

        throw new FileNotFoundException(name);
    }

    /// <summary>
    /// <c>setpriv --init-groups</c> resets the supplementary groups to those of <c>app</c>, which drops the
    /// group a compose <c>group_add</c> grants for the TPM device: the services then cannot open it and
    /// the status endpoint reports it unavailable. Found on real hardware (2026-10-20).
    /// </summary>
    [Theory]
    [InlineData("multi-container")]
    [InlineData("single-container")]
    [InlineData("identity")]
    public void Entrypoint_DropsToApp_KeepingTheGroupsTheRuntimeAdded(string deployDir)
    {
        // Comments explain why the flag is gone, so only code lines count.
        var text = string.Join('\n', File.ReadAllLines(Path.Combine(RepoDeployDir(), deployDir, "entrypoint.sh"))
            .Where(line => !line.TrimStart().StartsWith('#')));

        Assert.DoesNotContain("--init-groups", text);
        Assert.Contains("--groups ", text);
        // Root's own group 0 must not be carried into the unprivileged process.
        Assert.Contains("grep -vx 0", text);
    }

    private static string RepoDeployDir()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            var path = Path.Combine(dir.FullName, "deploy");
            if (Directory.Exists(Path.Combine(path, "multi-container")))
                return path;
        }

        throw new DirectoryNotFoundException("deploy");
    }

    [Fact]
    public void Entrypoint_ListsExactlyTheServicesTheDockerfilePublishes()
    {
        var listed = Regex.Match(Read("entrypoint.sh"), "VALID_SERVICES=\"([^\"]+)\"").Groups[1].Value
            .Split(' ', StringSplitOptions.RemoveEmptyEntries);
        // restorecheck is an operator tool run by restore-test, not a service the entrypoint can start.
        var published = Regex.Matches(Read("Dockerfile"), @"-o /app/(\w+)").Select(m => m.Groups[1].Value)
            .Where(name => name != "restorecheck");

        Assert.Equal(Services.Order(), listed.Order());
        Assert.Equal(Services.Order(), published.Order());
    }

    [Fact]
    public void Entrypoint_RejectsAMissingOrUnknownService_AndListsTheValidOnes()
    {
        var text = Read("entrypoint.sh");

        Assert.Contains("SERVICE=\"${SERVICE:-}\"", text);
        Assert.Contains("unknown or missing SERVICE", text);
        Assert.Contains("exit 64", text);
    }

    [Fact]
    public void ApiAndWeb_RefuseLocalhostAsTheHost_BecauseLocalhostInsideAContainerIsTheContainerItself()
    {
        // Both fetch the identity service's metadata from the advertised authority. In one container
        // localhost reaches it; across containers it never does, and the web app answered 500 (IDX20803).
        var text = Read("entrypoint.sh");

        Assert.Contains("QERTUM_HOST must not be 'localhost'", text);
        // Every spelling of "this container" gives the same IDX20803, not just the literal word.
        Assert.Contains("tr '[:upper:]' '[:lower:]'", text);
        foreach (var form in new[] { "localhost", "127.*", "::1", "0.0.0.0" })
            Assert.Contains(form, text);
        Assert.Matches(@"(?s)localhost.*apiservice\|webfrontend.*exit 64", text);
    }

    [Fact]
    public void Acme_AdvertisesItsOwnScheme_NotTheProxyOrientedOne_AndHasNoProxyTrustSetting()
    {
        // ACME must not sit behind a TLS-terminating proxy, so QERTUM_SCHEME (which exists for a proxy in
        // front of web, identity and API) must not flip its URLs to https. Only ACME_SCHEME does, set when
        // the acme container terminates TLS itself.
        var entrypoint = Read("entrypoint.sh");

        Assert.Contains("ACME_SCHEME=\"${ACME_SCHEME:-http}\"", entrypoint);
        Assert.Contains("Acme__BaseUrl=\"${ACME_SCHEME}://", entrypoint);
        Assert.Contains("Enrollment__AcmeDirectoryUrl=\"${ACME_SCHEME}://", entrypoint);
        Assert.DoesNotContain("TRUSTED_PROXIES", entrypoint);
        Assert.DoesNotContain("TRUSTED_PROXIES", Read("docker-compose.yml"));
        Assert.Contains("ACME_SCHEME", Read("docker-compose.yml"));
    }

    /// <summary>
    /// Behind the TLS proxy that QERTUM_SCHEME=https stands for, web, identity and API must honour
    /// X-Forwarded-Proto, or identity refuses every request as not https (found by the browser check,
    /// 2026-10-29). ACME and EST are never behind a proxy and must never trust the header, whatever is set.
    /// Runs the entrypoint's own block with sh.
    /// </summary>
    [Theory]
    [InlineData("webfrontend", "https", "true")]
    [InlineData("identityservice", "https", "true")]
    [InlineData("apiservice", "https", "true")]
    [InlineData("webfrontend", "http", "unset")]
    [InlineData("apiservice", "http", "unset")]
    [InlineData("acmeservice", "https", "unset")]
    [InlineData("estservice", "https", "unset")]
    [InlineData("queueconsumer", "https", "unset")]
    public void ForwardedHeaders_AreTrustedOnlyByTheProxiedServices_InHttpsMode(string service, string scheme, string expected)
    {
        var entrypoint = Read("entrypoint.sh");
        var start = entrypoint.IndexOf("case \"${SERVICE}\" in\n  webfrontend|identityservice|apiservice)", StringComparison.Ordinal);
        Assert.True(start >= 0, "the forwarded-headers block is missing");
        var block = entrypoint[start..(entrypoint.IndexOf("esac", start, StringComparison.Ordinal) + 4)];

        // ACME and EST start with the variable already set, as a careless override would leave it.
        var preset = service is "acmeservice" or "estservice" ? "export ASPNETCORE_FORWARDEDHEADERS_ENABLED=true\n" : "";
        var result = RunSh($"SERVICE={service}\nQERTUM_SCHEME={scheme}\n{preset}{block}\nprintf %s \"${{ASPNETCORE_FORWARDEDHEADERS_ENABLED-unset}}\"");

        Assert.Equal(expected, result);
    }

    internal static string RunSh(string script)
    {
        using var process = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("sh", ["-c", script])
        {
            RedirectStandardOutput = true,
            UseShellExecute = false,
            Environment = { ["ASPNETCORE_FORWARDEDHEADERS_ENABLED"] = null }
        })!;
        var output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        Assert.Equal(0, process.ExitCode);
        return output;
    }

    [Fact]
    public void EstService_RefusesToStartWithoutItsCertificate_RatherThanFallingBackToHttp()
    {
        var text = Read("entrypoint.sh");

        Assert.Contains("/run/est/tls.crt", text);
        Assert.Contains("/run/est/tls.key", text);
        Assert.Contains("https://0.0.0.0:8084", text);
        Assert.Contains("Kestrel__Certificates__Default__KeyPath", text);
        Assert.Matches(@"estservice requires[^\n]*\n[^\n]*exit 64|requires a server certificate", text);
    }

    [Fact]
    public void Dockerfile_PinsEveryBaseByDigest_AndHasNoSupervisor()
    {
        var text = Read("Dockerfile");

        foreach (var from in Regex.Matches(text, @"(?m)^FROM .*$").Select(m => m.Value))
            Assert.Matches(@"@sha256:[0-9a-f]{64}", from);
        Assert.DoesNotContain("supervisor", text, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("ENTRYPOINT", text);
    }

    [Fact]
    public void Healthcheck_KnowsEveryService()
    {
        var text = Read("healthcheck.sh");

        foreach (var service in Services)
            Assert.Contains(service, text);
        Assert.Contains("/dev/tcp/127.0.0.1", text);
    }

    private static string ServiceBlock(string compose, string name)
    {
        var match = Regex.Match(compose, $@"(?ms)^  {name}:\n(.*?)(?=^  \w[\w-]*:\n|^\w|\z)");
        Assert.True(match.Success, $"compose has no '{name}' service");
        return match.Groups[1].Value;
    }

    [Fact]
    public void Compose_HasOneContainerPerService_PlusRedis_AllNamedForTheBackupWrappers()
    {
        var compose = Read("docker-compose.yml");

        foreach (var service in Services)
        {
            var block = ServiceBlock(compose, service);
            Assert.Contains($"container_name: qertum-{service}", block);
            Assert.Contains($"SERVICE: {service}", block);
        }

        Assert.Contains("container_name: qertum-cache", ServiceBlock(compose, "cache"));
    }

    [Fact]
    public void Compose_NeverPublishesRedis()
    {
        var cache = ServiceBlock(Read("docker-compose.yml"), "cache");

        Assert.DoesNotContain("ports:", cache);
        Assert.Contains("redis:8.6@sha256:", cache);
    }

    [Fact]
    public void Compose_EveryQertumServiceSharesTheDataVolume_AndOnlyTheIntendedPortsArePublished()
    {
        var compose = Read("docker-compose.yml");

        Assert.Contains("- ${QERTUM_DATA:-qertum-data}:/data", compose);
        foreach (var service in Services)
            Assert.Contains("<<: *qertum-service", ServiceBlock(compose, service));
        Assert.DoesNotContain("ports:", ServiceBlock(compose, "queueconsumer"));
        Assert.Contains("/run/est/tls.crt:ro", ServiceBlock(compose, "estservice"));
        Assert.Contains("/run/est/tls.key:ro", ServiceBlock(compose, "estservice"));
    }

    [Fact]
    public void Compose_StartsInDependencyOrder_OnHealth()
    {
        var compose = Read("docker-compose.yml");

        Assert.Contains("condition: service_healthy", ServiceBlock(compose, "apiservice"));
        Assert.Contains("identityservice", ServiceBlock(compose, "apiservice"));
        foreach (var service in new[] { "webfrontend", "acmeservice", "estservice", "queueconsumer" })
            Assert.Contains("apiservice", ServiceBlock(compose, service));
    }

    [Fact]
    public void TpmOverride_GivesTheDeviceToEveryContainerThatBuildsTheKeyRing()
    {
        var tpm = Read("docker-compose.tpm.yml");

        // Every service is listed explicitly, so none can be left without the key ring's TPM.
        foreach (var service in Services)
        {
            var block = ServiceBlock(tpm, service);
            Assert.Contains("group_add:", block);
            Assert.Contains("devices:", block);
        }
    }

    [Theory]
    [InlineData("backup.sh", "single-container/backup.sh")]
    [InlineData("restore.sh", "single-container/restore.sh")]
    public void ShellWrappers_StopTheOtherContainers_DelegateUnchanged_AndRestartThemOnAnyExit(string name, string delegateTo)
    {
        var text = Read(name);

        Assert.Contains(delegateTo, text);
        Assert.Contains("qertum-apiservice", text);
        foreach (var other in new[] { "identityservice", "webfrontend", "acmeservice", "estservice", "queueconsumer" })
            Assert.Contains($"qertum-{other}", text);
        Assert.DoesNotContain("qertum-cache", text.Replace("# qertum-cache keeps running", string.Empty, StringComparison.Ordinal));
        Assert.Contains("trap restart_others EXIT", text);
        Assert.Contains("docker stop", text);
        Assert.Contains("docker start", text);
    }

    [Fact]
    public void RestoreTestWrapper_StopsNothing()
    {
        var text = Read("restore-test.sh");

        Assert.Contains("single-container/restore-test.sh", text);
        Assert.Contains("qertum-apiservice", text);
        Assert.DoesNotContain("docker stop", text);
    }

    [Theory]
    [InlineData("backup.ps1", "backup.ps1")]
    [InlineData("restore.ps1", "restore.ps1")]
    public void PowerShellWrappers_RestartTheOthersInFinally(string name, string inner)
    {
        var text = Read(name);

        Assert.Contains($"single-container\\{inner}", text);
        Assert.Contains("finally", text);
        Assert.Contains("docker start", text);
        Assert.Contains("qertum-apiservice", text);
    }

    [Theory]
    [InlineData("backup.ps1")]
    [InlineData("restore.ps1")]
    public void PowerShellWrappers_PassTheInnerExitCodeOn_NotTheRestartsOwn(string name)
    {
        // A failing native command does not throw, and the restarts in finally overwrite $LASTEXITCODE,
        // so without this a failed backup or restore reported success to the caller.
        var text = Read(name);

        var captured = text.IndexOf("$innerExit = $LASTEXITCODE", StringComparison.Ordinal);
        var finallyAt = text.IndexOf("finally {", StringComparison.Ordinal);
        var exited = text.IndexOf("exit $innerExit", StringComparison.Ordinal);
        Assert.True(captured >= 0 && captured < finallyAt, "the inner exit code must be captured before the restarts run");
        Assert.True(exited > finallyAt, "the script must exit with the captured code after the restarts");
    }
}
