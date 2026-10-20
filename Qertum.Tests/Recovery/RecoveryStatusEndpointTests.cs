using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;

namespace Qertum.Tests.Recovery;

public sealed class RecoveryStatusEndpointTests : IDisposable
{
    private readonly List<string> _tempDirectories = [];

    public void Dispose()
    {
        foreach (var dir in _tempDirectories)
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
        }
    }

    private string NewDataDirectory()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"recovery-endpoint-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        _tempDirectories.Add(dir);
        return dir;
    }

    private static WebApplicationFactory<ApiServiceProgram> CreateFactory(string dataDirectory)
    {
        var database = SharedInMemoryDatabase.Create();
        return new WebApplicationFactory<ApiServiceProgram>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("ASPNETCORE_ENVIRONMENT", "Test");
            builder.ConfigureTestServices(services =>
            {
                var descriptors = services
                    .Where(d => d.ServiceType == typeof(DbContextOptions<CertificateRequestDbContext>)
                             || d.ServiceType == typeof(CertificateRequestDbContext)
                             || d.ServiceType == typeof(SecretStorageOptions))
                    .ToList();
                foreach (var d in descriptors) services.Remove(d);

                database.ReplaceDbContext(services);
                services.AddSingleton(new SecretStorageOptions { DataDirectory = dataDirectory });

                services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = "Test";
                    options.DefaultChallengeScheme = "Test";
                }).AddScheme<Microsoft.AspNetCore.Authentication.AuthenticationSchemeOptions, TestAuthHandler>("Test", _ => { });

                services.AddSingleton(Qertum.Tests.Dashboard.StubCertificateGenerator.Returning(new CaStatusResponse()));
            });
        });
    }

    private static async Task EnsureDbAsync(WebApplicationFactory<ApiServiceProgram> factory, CancellationToken ct)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        await db.Database.OpenConnectionAsync(ct);
        await db.Database.EnsureCreatedAsync(ct);
    }

    [Fact]
    public async Task Get_WithNothingReported_ReturnsNotReportedForBoth()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory(NewDataDirectory());
        await EnsureDbAsync(factory, ct);
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");

        var response = await client.GetAsync("/v1/recovery-status", ct);
        response.EnsureSuccessStatusCode();

        var status = await response.Content.ReadFromJsonAsync<RecoveryStatus>(ct);
        Assert.Equal(RecoveryItemState.NotReported, status!.Backup.State);
        Assert.Equal(RecoveryItemState.NotReported, status.Restore.State);
    }

    [Fact]
    public async Task Get_ReturnsAReportedBackup_WithTheDefaultLimit()
    {
        var ct = TestContext.Current.CancellationToken;
        var dataDir = NewDataDirectory();
        Directory.CreateDirectory(Path.Combine(dataDir, "recovery"));
        var completed = DateTime.UtcNow.AddHours(-1).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture);
        File.WriteAllText(Path.Combine(dataDir, "recovery", "last-backup.json"),
            $$"""{"schemaVersion":1,"completedAtUtc":"{{completed}}","archiveName":"qertum-backup-x.tar.gz","reportedBy":"backup.sh"}""");
        await using var factory = CreateFactory(dataDir);
        await EnsureDbAsync(factory, ct);
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");

        var status = await client.GetFromJsonAsync<RecoveryStatus>("/v1/recovery-status", ct);

        Assert.Equal(RecoveryItemState.Fresh, status!.Backup.State);
        Assert.Equal(48, status.Backup.ThresholdHours);
        Assert.Equal("qertum-backup-x.tar.gz", status.Backup.ArchiveName);
    }

    [Fact]
    public async Task Get_WithoutAuth_Returns401()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory(NewDataDirectory());
        await EnsureDbAsync(factory, ct);

        var response = await factory.CreateClient().GetAsync("/v1/recovery-status", ct);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Get_WithoutSettingsEdit_Returns403()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory(NewDataDirectory());
        await EnsureDbAsync(factory, ct);
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test-NoRole");

        var response = await client.GetAsync("/v1/recovery-status", ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }
}
