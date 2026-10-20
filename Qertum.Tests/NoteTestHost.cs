using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Time.Testing;
using Qertum.Services;
using Qertum.Services.CertificateNotes;

namespace Qertum.Tests;

/// <summary>A real in-memory database with a fake clock and a recording audit log, for note tests.</summary>
internal sealed class NoteTestHost : IAsyncDisposable
{
    public static readonly DateTimeOffset Start = new(2026, 10, 14, 12, 0, 0, TimeSpan.Zero);

    private readonly SqliteConnection _connection;
    private int _sequence;

    public CertificateRequestDbContext Db { get; }
    public FakeTimeProvider Clock { get; } = new(Start);
    public MetadataTestHost.RecordingAudit Audit { get; } = new();
    public DeleteNotesBeforeSave Racer { get; }
    public DateTime Now => Clock.GetUtcNow().UtcDateTime;
    public CertificateNoteService Service { get; }

    private NoteTestHost(SqliteConnection connection, CertificateRequestDbContext db, DeleteNotesBeforeSave racer)
    {
        _connection = connection;
        Db = db;
        Racer = racer;
        Service = new CertificateNoteService(db, Audit, Clock);
    }

    public static async Task<NoteTestHost> CreateAsync()
    {
        var ct = TestContext.Current.CancellationToken;
        var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(ct);
        var racer = new DeleteNotesBeforeSave();
        var db = new CertificateRequestDbContext(
            new DbContextOptionsBuilder<CertificateRequestDbContext>().UseSqlite(connection).AddInterceptors(racer).Options,
            new EphemeralDataProtectionProvider());
        await db.Database.EnsureCreatedAsync(ct);
        db.Settings.Add(new CaSettings { Id = 1, PqcStage = PqcStage.Off });
        await db.SaveChangesAsync(ct);
        return new NoteTestHost(connection, db, racer);
    }

    /// <summary>A Pending request with a distinct common name.</summary>
    public async Task<CertificateRequest> RequestAsync(string commonName, CertificateRequestStatus status = CertificateRequestStatus.Pending)
    {
        var request = new CertificateRequest
        {
            CommonName = $"{++_sequence}-{commonName}", RequestedBy = "alice", Type = "WebServer", Status = status
        };
        Db.CertificateRequests.Add(request);
        await Db.SaveChangesAsync(TestContext.Current.CancellationToken);
        return request;
    }

    public async ValueTask DisposeAsync()
    {
        await Db.DisposeAsync();
        await _connection.DisposeAsync();
    }

    /// <summary>
    /// Once armed, deletes every note just before the next save: the window between a service reading a note and
    /// saving its change, where another request can delete it.
    /// </summary>
    internal sealed class DeleteNotesBeforeSave : Microsoft.EntityFrameworkCore.Diagnostics.SaveChangesInterceptor
    {
        public bool Armed { get; set; }

        public override async ValueTask<Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<int>> SavingChangesAsync(
            Microsoft.EntityFrameworkCore.Diagnostics.DbContextEventData eventData,
            Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (Armed)
            {
                Armed = false;
                await eventData.Context!.Database.ExecuteSqlRawAsync("DELETE FROM CertificateNotes", cancellationToken);
            }
            return result;
        }
    }
}
