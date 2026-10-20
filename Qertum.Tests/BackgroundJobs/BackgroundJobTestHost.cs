using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using Qertum.Services;
using Qertum.Services.BackgroundJobs;
using Qertum.Services.Issuers;
using Qertum.Services.Lifecycle;
using Qertum.Services.Policies;
using Qertum.Tests.Lifecycle;

namespace Qertum.Tests.BackgroundJobs;

/// <summary>
/// A QueueConsumer-shaped container over a shared in-memory database, a real CA in a temp
/// directory, an in-memory distributed cache and a fake clock.
/// </summary>
internal sealed class BackgroundJobTestHost : IAsyncDisposable
{
    private readonly string _caDirectory;

    private BackgroundJobTestHost(string caDirectory, SharedInMemoryDatabase database, ServiceProvider services,
        FakeTimeProvider clock, RecordingDiagnosticEventLog diagnostics, IDataProtectionProvider dataProtection)
    {
        _caDirectory = caDirectory;
        DataProtection = dataProtection;
        Database = database;
        Services = services;
        Clock = clock;
        Diagnostics = diagnostics;
    }

    public string CaDirectory => _caDirectory;
    public IDataProtectionProvider DataProtection { get; }
    public FakeTimeProvider Clock { get; }
    public RecordingDiagnosticEventLog Diagnostics { get; }
    public SharedInMemoryDatabase Database { get; }
    public ServiceProvider Services { get; }

    public static BackgroundJobTestHost Create(bool initializeCa = true, Action<IServiceCollection>? configure = null)
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 9, 25, 8, 0, 0, TimeSpan.Zero));
        var diagnostics = new RecordingDiagnosticEventLog();
        var database = SharedInMemoryDatabase.Create(createSchema: true, seedSettings: false);
        var caDirectory = Path.Combine(Path.GetTempPath(), "CaData-" + Guid.NewGuid().ToString("N"));

        var dataProtection = new EphemeralDataProtectionProvider();
        var generator = new CertificateGenerator(dataProtection,
            new CaDataOptions { Directory = caDirectory }, NullLogger<CertificateGenerator>.Instance,
            timeProvider: clock);
        if (initializeCa)
            generator.GenerateCa(new GenerateCaRequest
            {
                CommonName = "Background Job Test Root",
                KeyAlgorithm = CertificateKeyAlgorithm.Rsa,
                ValidityDays = 365
            });

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IDataProtectionProvider>(dataProtection);
        services.AddSingleton(new CaDataOptions { Directory = caDirectory });
        database.ReplaceDbContext(services);
        services.AddSingleton<TimeProvider>(clock);
        services.AddSingleton<IDiagnosticEventLog>(diagnostics);
        services.AddSingleton<ICertificateGenerator>(generator);
        services.AddDistributedMemoryCache();
        services.AddSingleton<IAuditLogService, NoAuditLog>();
        services.AddSingleton<IWebhookService, NoWebhooks>();
        services.AddSingleton<IIssuancePolicyEvaluator, IssuancePolicyEvaluator>();
        services.AddScoped<IIssuancePolicyService, IssuancePolicyService>();
        services.AddScoped<ICertificateRequestService, CertificateRequestService>();
        services.AddScoped<CrlPublisher>();
        services.AddIssuerRegistry();
        services.AddScoped<IBackgroundJobQueue, BackgroundJobQueue>();
        services.AddSingleton<IBackgroundJobSignal, BackgroundJobChannel>();
        configure?.Invoke(services);

        return new BackgroundJobTestHost(caDirectory, database, services.BuildServiceProvider(), clock, diagnostics, dataProtection);
    }

    public async Task<CaSettings?> SettingsAsync()
    {
        await using var db = Database.CreateContext();
        return await db.Settings.AsNoTracking().SingleOrDefaultAsync();
    }

    public async ValueTask DisposeAsync()
    {
        await Services.DisposeAsync();
        if (Directory.Exists(_caDirectory))
            try { Directory.Delete(_caDirectory, recursive: true); } catch { /* best effort */ }
    }

    private sealed class NoAuditLog : IAuditLogService
    {
        public Task LogAsync(string action, string performedBy, Guid? resourceId = null,
            string? resourceName = null, string? detail = null, CancellationToken cancellationToken = default)
            => Task.CompletedTask;

        public Task<IReadOnlyList<AuditLogEntry>> GetAllAsync(int page = 1, int pageSize = 100,
            CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<AuditLogEntry>>([]);
    }

    private sealed class NoWebhooks : IWebhookService
    {
        public Task<IReadOnlyList<Webhook>> GetAllAsync(CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<Webhook>>([]);
        public Task<Webhook?> GetByIdAsync(WebhookId id, CancellationToken cancellationToken = default) => Task.FromResult<Webhook?>(null);
        public Task<Webhook> CreateAsync(Webhook webhook, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult(webhook);
        public Task<Webhook?> UpdateAsync(WebhookId id, Webhook webhook, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult<Webhook?>(null);
        public Task<bool> DeleteAsync(WebhookId id, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult(false);
        public Task EnqueueEventAsync(WebhookEvent webhookEvent, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}
