using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Aspire.Hosting;
using Aspire.Hosting.ApplicationModel;

namespace Qertum.Tests.Aspire;

public sealed class AspireIntegrationFixture : IAsyncLifetime
{
    private static readonly TimeSpan StartTimeout = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan HealthyTimeout = TimeSpan.FromMinutes(3);

    private IReadOnlyList<string> _resourceNames = [];

    public DistributedApplication App { get; private set; } = null!;

    public HttpClient ApiClientAsAdmin  { get; private set; } = null!;
    public HttpClient ApiClientAsViewer { get; private set; } = null!;
    public HttpClient ApiClientAnon     { get; private set; } = null!;
    public HttpClient WebClient         { get; private set; } = null!;

    public async ValueTask InitializeAsync()
    {
        var appBuilder = await DistributedApplicationTestingBuilder
            .CreateAsync<Projects.Qertum_AppHost>();
        appBuilder.Services.ConfigureHttpClientDefaults(b => b.AddStandardResilienceHandler());

        // qertum-test-m2m (admin) and qertum-test-viewer carry secrets committed to this
        // repository, so the identity provider seeds them only when asked and deletes them on any
        // start where they are not. The ask lives here rather than in AppHost.cs so a plain
        // `dotnet run --project Qertum.AppHost` does not create them either.
        var identityService = appBuilder.Resources
            .OfType<ProjectResource>()
            .Single(r => r.Name == "identityservice");
        appBuilder.CreateResourceBuilder(identityService)
            .WithEnvironment("IdentityService__SeedTestClients", "true");

        _resourceNames = appBuilder.Resources.Select(r => r.Name).ToList();

        // Building and starting the app starts the container runtime and pulls images. With no limit a
        // Docker that is stuck or unreachable (as on the CI runner) hung the whole run without a word.
        using (var startCts = new CancellationTokenSource(StartTimeout))
        {
            try
            {
                App = await appBuilder.BuildAsync(startCts.Token);
                await App.StartAsync(startCts.Token);
            }
            catch (OperationCanceledException) when (startCts.IsCancellationRequested)
            {
                throw new TimeoutException(
                    $"The Aspire app did not start within {StartTimeout.TotalMinutes:0} minutes; is the container runtime reachable? {await DescribeResourcesAsync()}");
            }
        }

        using var cts = new CancellationTokenSource(HealthyTimeout);
        var ct = cts.Token;
        try
        {
            await App.ResourceNotifications.WaitForResourceHealthyAsync("identityservice", ct);
            await App.ResourceNotifications.WaitForResourceHealthyAsync("apiservice", ct);
            await App.ResourceNotifications.WaitForResourceHealthyAsync("webfrontend", ct);
        }
        catch (OperationCanceledException) when (cts.IsCancellationRequested)
        {
            throw new TimeoutException(
                $"identityservice, apiservice and webfrontend were not all healthy within {HealthyTimeout.TotalMinutes:0} minutes. {await DescribeResourcesAsync()}");
        }

        using var idClient = App.CreateHttpClient("identityservice", "https");
        ApiClientAnon    = App.CreateHttpClient("apiservice");
        ApiClientAsAdmin  = await BuildAuthedApiClient("qertum-test-m2m",    "test-m2m-secret",     idClient);
        ApiClientAsViewer = await BuildAuthedApiClient("qertum-test-viewer", "test-viewer-secret",  idClient);
        WebClient        = App.CreateHttpClient("webfrontend");

        await ApiClientAsAdmin.PutAsJsonAsync("/v1/permissions/viewer",
            new { Permissions = new[] { "certificates.view" } },
            TestContext.Current.CancellationToken);

        // The CA default is PQC stage Enforce; the suites issue RSA certificates and an RSA root, so
        // they run with enforcement off. Admin only, which is what the m2m client is.
        (await ApiClientAsAdmin.PutAsJsonAsync("/v1/settings/pqc-stage", new { stage = "Off" }, ct))
            .EnsureSuccessStatusCode();

        await InitializeCaAsync(ct);
    }

    private async Task InitializeCaAsync(CancellationToken ct)
    {
        // Check whether a CA is already set up (e.g. from a previous test run that reused the DB).
        var statusResp = await ApiClientAsAdmin.GetAsync("/v1/ca/status", ct);
        if (statusResp.IsSuccessStatusCode)
        {
            var status = await statusResp.Content.ReadFromJsonAsync<JsonDocument>(ct);
            if (status?.RootElement.GetProperty("isInitialized").GetBoolean() == true)
                return;
        }

        // Create a Root CA request. If one already exists from an interrupted previous run
        // (409), recover its ID from the status endpoint and continue from the approve step.
        string requestId;
        var generateResp = await ApiClientAsAdmin.PostAsJsonAsync("/v1/ca/generate", new
        {
            commonName = "Integration Test Root CA",
            keyAlgorithm = "RSA",
            validityDays = 3650
        }, ct);

        if (generateResp.StatusCode == HttpStatusCode.Conflict)
        {
            var statusAgain = await ApiClientAsAdmin.GetAsync("/v1/ca/status", ct);
            statusAgain.EnsureSuccessStatusCode();
            var statusDoc = await statusAgain.Content.ReadFromJsonAsync<JsonDocument>(ct);
            var pendingId = statusDoc!.RootElement.GetProperty("pendingRootCaRequestId").GetString()
                ?? throw new InvalidOperationException(
                    "POST /ca/generate returned 409 but GET /ca/status has no pendingRootCaRequestId.");
            requestId = pendingId;
        }
        else
        {
            generateResp.EnsureSuccessStatusCode();
            var certRequest = await generateResp.Content.ReadFromJsonAsync<JsonDocument>(ct);
            requestId = certRequest!.RootElement.GetProperty("id").GetString()!;
        }

        // Approve the Root CA request. Ignore 409 — it means a previous run already approved it.
        var approveResp = await ApiClientAsAdmin.PostAsync($"/v1/certificate-requests/{requestId}/approve", null, ct);
        if (approveResp.StatusCode != HttpStatusCode.Conflict)
            approveResp.EnsureSuccessStatusCode();

        // Poll until the queue consumer has generated the CA files.
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(TimeSpan.FromMinutes(2));
        while (!timeoutCts.IsCancellationRequested)
        {
            await Task.Delay(TimeSpan.FromSeconds(2), timeoutCts.Token);
            var pollResp = await ApiClientAsAdmin.GetAsync("/v1/ca/status", timeoutCts.Token);
            if (!pollResp.IsSuccessStatusCode) continue;
            var pollDoc = await pollResp.Content.ReadFromJsonAsync<JsonDocument>(timeoutCts.Token);
            if (pollDoc?.RootElement.GetProperty("isInitialized").GetBoolean() == true)
                return;
        }
    }

    private async Task<HttpClient> BuildAuthedApiClient(
        string clientId, string clientSecret, HttpClient idClient)
    {
        var resp = await idClient.PostAsync("/connect/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"]    = "client_credentials",
                ["client_id"]     = clientId,
                ["client_secret"] = clientSecret,
                ["scope"]         = "qertum-api"
            }), TestContext.Current.CancellationToken);
        resp.EnsureSuccessStatusCode();
        var doc   = await resp.Content.ReadFromJsonAsync<JsonDocument>(TestContext.Current.CancellationToken);
        var token = doc!.RootElement.GetProperty("access_token").GetString()!;

        var http = App.CreateHttpClient("apiservice");
        http.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", token);
        return http;
    }

    /// <summary>
    /// The state and health of every resource, so a timeout says which one never came up, followed by the last
    /// log lines of any resource that is running (or has stopped) but is not healthy: that line is usually the reason.
    /// </summary>
    private async Task<string> DescribeResourcesAsync()
    {
        var parts = new List<string>();
        var troubled = new List<string>();
        foreach (var name in _resourceNames)
        {
            if (App is null || !App.ResourceNotifications.TryGetCurrentState(name, out var resourceEvent))
            {
                parts.Add($"{name}=not started");
                continue;
            }

            var state = resourceEvent.Snapshot.State?.Text ?? "?";
            var health = resourceEvent.Snapshot.HealthStatus?.ToString() ?? "-";
            parts.Add($"{name}={state}/{health}");
            if (state is "Running" or "Finished" or "Exited" or "FailedToStart" && health != "Healthy")
                troubled.Add(name);
        }

        var text = "Resources: " + string.Join(", ", parts);
        foreach (var name in troubled)
            text += $"\nLast log lines of {name}:\n{await TailLogAsync(name)}";
        return text;
    }

    private async Task<string> TailLogAsync(string resourceName, int lines = 25)
    {
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var collected = new List<string>();
            await foreach (var batch in App.Services.GetRequiredService<ResourceLoggerService>()
                               .GetAllAsync(resourceName).WithCancellation(cts.Token))
                collected.AddRange(batch.Select(line => line.Content));
            return collected.Count == 0 ? "  (no log lines)" : string.Join("\n", collected.TakeLast(lines).Select(l => "  " + l));
        }
        catch (Exception ex)
        {
            return $"  (could not read the log: {ex.GetType().Name})";
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (App is null) return; // start failed or timed out before there was an app
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        try { await App.StopAsync(cts.Token); } catch { /* best-effort stop */ }
        await App.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(15));
    }
}
