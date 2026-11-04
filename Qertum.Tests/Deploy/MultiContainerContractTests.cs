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
        // ACME's own proxy trust list was removed for good; QERTUM_TRUSTED_PROXIES applies to web, identity and API
        // only, which ForwardedHeaders_AreTrustedOnlyByTheProxiedServices_InHttpsMode runs.
        Assert.DoesNotContain("ACME_TRUSTED_PROXIES", entrypoint);
        Assert.DoesNotContain("ACME_TRUSTED_PROXIES", Read("docker-compose.yml"));
        Assert.Contains("ACME_SCHEME", Read("docker-compose.yml"));
    }

    /// <summary>
    /// Behind the TLS proxy that QERTUM_SCHEME=https stands for, web, identity and API must honour
    /// X-Forwarded-Proto, or identity refuses every request as not https (found by the browser check,
    /// 2026-10-29), and only from QERTUM_TRUSTED_PROXIES. ACME and EST are never behind a proxy and must never
    /// trust the header, whatever is set. Runs the entrypoint's own block with sh.
    /// </summary>
    [Theory]
    [InlineData("webfrontend", "https", "true|10.0.0.0/8")]
    [InlineData("identityservice", "https", "true|10.0.0.0/8")]
    [InlineData("apiservice", "https", "true|10.0.0.0/8")]
    [InlineData("webfrontend", "http", "unset|unset")]
    [InlineData("apiservice", "http", "unset|unset")]
    [InlineData("acmeservice", "https", "unset|unset")]
    [InlineData("estservice", "https", "unset|unset")]
    [InlineData("queueconsumer", "https", "unset|unset")]
    public void ForwardedHeaders_AreTrustedOnlyByTheProxiedServices_InHttpsMode(string service, string scheme, string expected)
    {
        // ACME and EST start with the variable already set, as a careless override would leave it.
        var preset = service is "acmeservice" or "estservice" ? "export ASPNETCORE_FORWARDEDHEADERS_ENABLED=true\n" : "";
        var result = RunSh($"SERVICE={service}\nQERTUM_SCHEME={scheme}\nQERTUM_TRUSTED_PROXIES=10.0.0.0/8\n{preset}{ForwardedHeadersBlock()}\n" +
                           "printf %s \"${ASPNETCORE_FORWARDEDHEADERS_ENABLED-unset}|${ForwardedHeaders__TrustedProxies-unset}\"");

        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData("webfrontend")]
    [InlineData("identityservice")]
    [InlineData("apiservice")]
    public void HttpsMode_RefusesToStartWithoutATrustedProxy(string service)
    {
        // Forwarded headers trusted from everyone would let any client reaching the port claim https or any address.
        RunSh($"SERVICE={service}\nQERTUM_SCHEME=https\n{ForwardedHeadersBlock()}", expectedExit: 64);
    }

    /// <summary>
    /// OpenIddict's https rule follows QERTUM_SCHEME: with https the published identity port refuses plain http, which
    /// was accepted whatever the scheme until 1.0.0-rc4.3. An explicit value still wins.
    /// </summary>
    [Theory]
    [InlineData("https", "", "false")]
    [InlineData("http", "", "true")]
    [InlineData("https", "export IdentityService__DisableTransportSecurity=true\n", "true")]
    public void IdentityTransportSecurity_FollowsTheScheme(string scheme, string preset, string expected)
    {
        var entrypoint = Read("entrypoint.sh");
        var start = entrypoint.IndexOf("if [ \"${QERTUM_SCHEME}\" = \"https\" ]; then insecure_default=false", StringComparison.Ordinal);
        Assert.True(start >= 0, "the transport-security block is missing");
        var end = entrypoint.IndexOf('\n', entrypoint.IndexOf("export IdentityService__DisableTransportSecurity=", start, StringComparison.Ordinal));
        var result = RunSh($"QERTUM_SCHEME={scheme}\n{preset}{entrypoint[start..end]}\nprintf %s \"$IdentityService__DisableTransportSecurity\"");

        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData("", 64)]
    [InlineData("true", 0)]
    public void MultiContainerHttp_RequiresExplicitInsecureOptIn(string optIn, int expectedExit)
    {
        var entrypoint = Read("entrypoint.sh");
        var start = entrypoint.IndexOf("# Plain HTTP exposure requires", StringComparison.Ordinal);
        Assert.True(start >= 0, "the explicit insecure HTTP guard is missing");
        var end = entrypoint.IndexOf("# Every spelling", start, StringComparison.Ordinal);
        RunSh($"SERVICE=webfrontend\nQERTUM_SCHEME=http\nQERTUM_ALLOW_INSECURE_HTTP={optIn}\n" + entrypoint[start..end], expectedExit);
    }

    private static string ForwardedHeadersBlock()
    {
        var entrypoint = Read("entrypoint.sh");
        var start = entrypoint.IndexOf("case \"${SERVICE}\" in\n  webfrontend|identityservice|apiservice)", StringComparison.Ordinal);
        Assert.True(start >= 0, "the forwarded-headers block is missing");
        return entrypoint[start..(entrypoint.IndexOf("esac", start, StringComparison.Ordinal) + 4)];
    }

    internal static string RunSh(string script, int expectedExit = 0)
    {
        using var process = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("sh", ["-c", script])
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            Environment =
            {
                ["ASPNETCORE_FORWARDEDHEADERS_ENABLED"] = null,
                ["QERTUM_TRUSTED_PROXIES"] = null,
                ["ForwardedHeaders__TrustedProxies"] = null
            }
        })!;
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        process.WaitForExit();
        Assert.True(process.ExitCode == expectedExit, $"exit {process.ExitCode}, expected {expectedExit}: {error}");
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
    public void Compose_NeverPublishesTheCache()
    {
        var cache = ServiceBlock(Read("docker-compose.yml"), "cache");

        Assert.DoesNotContain("ports:", cache);
        Assert.Contains("valkey/valkey:9.1@sha256:", cache);
        Assert.Contains("valkey-server", cache);
    }

    [Fact]
    public void Compose_RestrictsIdentityAndWebToTheirOwnState_AndPreservesTheBackupVolume()
    {
        var compose = Read("docker-compose.yml");

        Assert.DoesNotContain("volumes:", compose[..compose.IndexOf("services:", StringComparison.Ordinal)]);
        var identity = ServiceBlock(compose, "identityservice");
        Assert.Contains("subpath: identity", identity);
        Assert.Contains("target: /data/identity", identity);
        var web = ServiceBlock(compose, "webfrontend");
        Assert.Contains("subpath: web", web);
        Assert.Contains("target: /home/app/.aspnet/DataProtection-Keys", web);
        foreach (var service in new[] { "apiservice", "acmeservice", "estservice", "queueconsumer" })
            Assert.Contains("${QERTUM_DATA:-qertum-data}:/data", ServiceBlock(compose, service));
        Assert.Contains("condition: service_completed_successfully", identity);
        Assert.Contains("condition: service_completed_successfully", web);
        Assert.DoesNotContain("ports:", ServiceBlock(compose, "queueconsumer"));
        Assert.Contains("/run/est/tls.crt:ro", ServiceBlock(compose, "estservice"));
        Assert.Contains("/run/est/tls.key:ro", ServiceBlock(compose, "estservice"));
    }

    [Fact]
    public void BrowserAndApiPorts_DefaultToLoopback_InBothLayouts()
    {
        var multi = Read("docker-compose.yml");
        foreach (var service in new[] { "identityservice", "webfrontend", "apiservice" })
            Assert.Contains("${QERTUM_BIND_ADDRESS:-127.0.0.1}:", ServiceBlock(multi, service));
        var single = File.ReadAllText(Path.Combine(RepoDeployDir(), "single-container", "docker-compose.yml"));
        foreach (var port in new[] { "8090:8080", "8081:8081", "8082:8082" })
            Assert.Contains("${QERTUM_BIND_ADDRESS:-127.0.0.1}:" + port, single);
    }

    [Fact]
    public void BindOverride_PreservesExistingLayout_WithoutMountingCaStateIntoIdentityOrWeb()
    {
        var bind = Read("docker-compose.bind.yml");
        Assert.Contains("${QERTUM_DATA:?", bind);
        Assert.Contains("/identity:/data/identity", ServiceBlock(bind, "identityservice"));
        Assert.Contains("/web:/home/app/.aspnet/DataProtection-Keys", ServiceBlock(bind, "webfrontend"));
        Assert.DoesNotContain(":/data\n", ServiceBlock(bind, "identityservice"));
        Assert.DoesNotContain(":/data\n", ServiceBlock(bind, "webfrontend"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void RenderedCompose_RestrictsTheMountGraph_AndBindsBrowserPortsToLoopback(bool bind)
    {
        var file = Path.Combine(RepoDeployDir(), "multi-container", "docker-compose.yml");
        var args = new List<string> { "compose", "-f", file };
        if (bind) args.AddRange(["-f", Path.Combine(Path.GetDirectoryName(file)!, "docker-compose.bind.yml")]);
        args.AddRange(["config", "--format", "json"]);
        var info = new System.Diagnostics.ProcessStartInfo("docker", args)
        {
            RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false
        };
        info.Environment["QERTUM_IMAGE"] = "qertum-services:test";
        info.Environment["QERTUM_HOST"] = "ca.example.test";
        info.Environment["QERTUM_EST_TLS_CERT"] = "/example/tls.crt";
        info.Environment["QERTUM_EST_TLS_KEY"] = "/example/tls.key";
        info.Environment["QERTUM_BIND_ADDRESS"] = null;
        info.Environment["QERTUM_DATA"] = bind ? "/existing-qertum-data" : null;
        System.Diagnostics.Process? process;
        try { process = System.Diagnostics.Process.Start(info); }
        catch (System.ComponentModel.Win32Exception) { Assert.Skip("Docker Compose CLI is unavailable."); return; }
        using (process)
        {
            Assert.NotNull(process);
            var output = process.StandardOutput.ReadToEnd();
            var error = process.StandardError.ReadToEnd();
            process.WaitForExit();
            if (error.Contains("is not a docker command", StringComparison.Ordinal))
            { Assert.Skip("Docker Compose CLI is unavailable."); return; }
            Assert.True(process.ExitCode == 0, error);
            using var json = System.Text.Json.JsonDocument.Parse(output);
            var services = json.RootElement.GetProperty("services");
            foreach (var service in new[] { "identityservice", "webfrontend" })
            {
                var mounts = services.GetProperty(service).GetProperty("volumes").EnumerateArray().ToList();
                var mount = Assert.Single(mounts);
                var identity = service == "identityservice";
                Assert.Equal(identity ? "/data/identity" : "/home/app/.aspnet/DataProtection-Keys", mount.GetProperty("target").GetString());
                if (bind)
                    Assert.Equal("/existing-qertum-data/" + (identity ? "identity" : "web"), mount.GetProperty("source").GetString());
                else
                    Assert.Equal(identity ? "identity" : "web", mount.GetProperty("volume").GetProperty("subpath").GetString());
            }
            foreach (var service in new[] { "identityservice", "webfrontend", "apiservice" })
                foreach (var port in services.GetProperty(service).GetProperty("ports").EnumerateArray())
                    Assert.Equal("127.0.0.1", port.GetProperty("host_ip").GetString());
            var apiData = Assert.Single(services.GetProperty("apiservice").GetProperty("volumes").EnumerateArray());
            Assert.Equal("/data", apiData.GetProperty("target").GetString());
        }
    }

    [Fact]
    public void Initializer_FailedLegacySecretCopy_IsNotPublished_AndRetryPreservesTheOriginal()
    {
        if (OperatingSystem.IsWindows()) { Assert.Skip("The initializer is a Unix shell script."); return; }
        var directory = Directory.CreateTempSubdirectory("qertum-init-secret-").FullName;
        try
        {
            var data = Directory.CreateDirectory(Path.Combine(directory, "data")).FullName;
            var stubs = Directory.CreateDirectory(Path.Combine(directory, "stubs")).FullName;
            var original = "complete legacy secret";
            File.WriteAllText(Path.Combine(data, ".api-introspection-secret"), original);
            var cat = Path.Combine(stubs, "cat");
            File.WriteAllText(cat, "#!/bin/sh\nif [ \"${FAIL_CAT:-}\" = true ]; then printf truncated; exit 71; fi\nexec /bin/cat \"$@\"\n");
            File.SetUnixFileMode(cat, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            var chown = Path.Combine(stubs, "chown");
            File.WriteAllText(chown, "#!/bin/sh\nexit 0\n");
            File.SetUnixFileMode(chown, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            // Redirect only the fixed mount root into controlled test data; execute the initializer's actual commands.
            var script = Read("init-data.sh").Replace("/data", data, StringComparison.Ordinal);
            int Run(bool fail)
            {
                using var process = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("sh", ["-c", script])
                {
                    UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true,
                    Environment = { ["PATH"] = stubs + Path.PathSeparator + Environment.GetEnvironmentVariable("PATH"),
                        ["FAIL_CAT"] = fail ? "true" : "false" }
                })!;
                process.StandardOutput.ReadToEnd();
                process.StandardError.ReadToEnd();
                process.WaitForExit();
                return process.ExitCode;
            }
            Assert.NotEqual(0, Run(fail: true));
            var destination = Path.Combine(data, "identity", ".api-introspection-secret");
            Assert.False(File.Exists(destination), "A failed copy must not publish a truncated seed secret.");
            Assert.Empty(Directory.GetFiles(data, ".api-introspection-secret.tmp*"));
            Assert.Equal(original, File.ReadAllText(Path.Combine(data, ".api-introspection-secret")));
            Assert.Equal(0, Run(fail: false));
            Assert.Equal(original, File.ReadAllText(destination));
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(destination));
            Assert.Empty(Directory.GetFiles(data, ".api-introspection-secret.tmp*"));
            File.WriteAllText(destination, "existing identity secret");
            Assert.Equal(0, Run(fail: true));
            Assert.Equal("existing identity secret", File.ReadAllText(destination));
            File.Delete(destination);
            var unrelated = Path.Combine(data, "unrelated-secret");
            File.WriteAllText(unrelated, "never replace this");
            File.CreateSymbolicLink(destination, unrelated);
            Assert.NotEqual(0, Run(fail: false));
            Assert.Equal("never replace this", File.ReadAllText(unrelated));
            File.Delete(destination);
            Directory.CreateDirectory(destination);
            Assert.NotEqual(0, Run(fail: false));
            Assert.Empty(Directory.GetFileSystemEntries(destination));
        }
        finally { Directory.Delete(directory, recursive: true); }
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
