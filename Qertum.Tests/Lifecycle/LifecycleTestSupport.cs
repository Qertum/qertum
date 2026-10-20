using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Qertum.Services;
using Qertum.Services.Lifecycle;

namespace Qertum.Tests.Lifecycle;

/// <summary>A real SerilogAuditLogService over a temp audit directory and an in-memory database.</summary>
internal sealed class AuditLogHarness : IDisposable
{
    private readonly ServiceProvider _provider;

    public AuditLogHarness(TimeProvider? time = null, int bufferingTimeLimitMs = 50)
    {
        AuditDirectory = Path.Combine(Path.GetTempPath(), "qertum-audit-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(AuditDirectory);
        Database = SharedInMemoryDatabase.Create(createSchema: true);

        var services = new ServiceCollection();
        services.AddSingleton<IDataProtectionProvider, EphemeralDataProtectionProvider>();
        Database.ReplaceDbContext(services);
        _provider = services.BuildServiceProvider();

        var auditOptions = Options.Create(new AuditLogOptions
        {
            File = new AuditLogOptions.FileLogOptions { Path = Path.Combine(AuditDirectory, "audit-.clef") }
        });
        Service = new SerilogAuditLogService(
            auditOptions,
            new AuditLogFileReader(auditOptions),
            _provider.GetRequiredService<IServiceScopeFactory>(),
            Options.Create(new LifecycleEventsOptions { BufferingTimeLimitMs = bufferingTimeLimitMs }),
            time ?? TimeProvider.System);
    }

    public string AuditDirectory { get; }
    public SharedInMemoryDatabase Database { get; }
    public SerilogAuditLogService Service { get; }

    private bool _flushed;

    /// <summary>
    /// Every CLEF line written so far. The file sink writes synchronously and holds the file open with
    /// <c>shared: true</c>, so this reads with <see cref="FileShare.ReadWrite"/> and needs no flush.
    /// </summary>
    public string[] AuditFileLines() => Directory.EnumerateFiles(AuditDirectory, "*.clef")
        .SelectMany(f =>
        {
            using var stream = new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var reader = new StreamReader(stream);
            return reader.ReadToEnd().Split('\n', StringSplitOptions.RemoveEmptyEntries);
        })
        .ToArray();

    /// <summary>Disposes the service, which flushes every pending table batch. Idempotent.</summary>
    public void Flush()
    {
        if (_flushed) return;
        _flushed = true;
        Service.Dispose();
    }

    public void Dispose()
    {
        // Bounded: with a broken table Serilog may still be retrying a batch, and a test must not wait
        // out its ten-minute retry window.
        Task.Run(Flush).Wait(TimeSpan.FromSeconds(5));
        _provider.Dispose();
        try { Directory.Delete(AuditDirectory, recursive: true); } catch (IOException) { }
    }
}
