using System.Reflection;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Logging.Abstractions;
using Qertum.Services;
using Qertum.Services.Dashboard;

namespace Qertum.Tests.Dashboard;

/// <summary>In-memory SQLite database with the full schema, plus an optional command interceptor.</summary>
internal sealed class AttentionTestDb : IAsyncDisposable
{
    private AttentionTestDb(SqliteConnection connection, CertificateRequestDbContext db)
    {
        Connection = connection;
        Db = db;
    }

    public SqliteConnection Connection { get; }

    public CertificateRequestDbContext Db { get; }

    public static async Task<AttentionTestDb> CreateAsync(CancellationToken ct, DbCommandInterceptor? interceptor = null)
    {
        var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(ct);
        var builder = new DbContextOptionsBuilder<CertificateRequestDbContext>().UseSqlite(connection);
        if (interceptor is not null)
            builder.AddInterceptors(interceptor);
        var db = new CertificateRequestDbContext(builder.Options, new EphemeralDataProtectionProvider());
        await db.Database.EnsureCreatedAsync(ct);
        return new AttentionTestDb(connection, db);
    }

    public IAttentionService CreateService(TimeProvider time, ICertificateGenerator? generator = null,
        Qertum.Services.Recovery.IRecoveryStatusService? recovery = null) =>
        new AttentionService(Db, generator ?? StubCertificateGenerator.Returning(new CaStatusResponse()),
            time, NullLogger<AttentionService>.Instance, recovery: recovery);

    public async ValueTask DisposeAsync()
    {
        await Db.DisposeAsync();
        await Connection.DisposeAsync();
    }
}

internal sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
{
    public override DateTimeOffset GetUtcNow() => now;
}

/// <summary>Records every SQL command text the context sends.</summary>
internal sealed class RecordingCommandInterceptor : DbCommandInterceptor
{
    public List<string> Commands { get; } = [];

    public override ValueTask<InterceptionResult<System.Data.Common.DbDataReader>> ReaderExecutingAsync(
        System.Data.Common.DbCommand command, CommandEventData eventData,
        InterceptionResult<System.Data.Common.DbDataReader> result, CancellationToken cancellationToken = default)
    {
        Commands.Add(command.CommandText);
        return base.ReaderExecutingAsync(command, eventData, result, cancellationToken);
    }

    public override ValueTask<InterceptionResult<object>> ScalarExecutingAsync(
        System.Data.Common.DbCommand command, CommandEventData eventData,
        InterceptionResult<object> result, CancellationToken cancellationToken = default)
    {
        Commands.Add(command.CommandText);
        return base.ScalarExecutingAsync(command, eventData, result, cancellationToken);
    }
}

/// <summary>
/// An <see cref="ICertificateGenerator"/> that answers only <c>GetCaStatus</c>; every other member
/// throws, so a check that reaches for anything else fails loudly.
/// </summary>
public class StubCertificateGenerator : DispatchProxy
{
    private Func<CaStatusResponse> _status = () => new CaStatusResponse();

    public static ICertificateGenerator Returning(CaStatusResponse status) => Build(() => status);

    public static ICertificateGenerator Throwing() =>
        Build(() => throw new InvalidOperationException("CA status unavailable"));

    private static ICertificateGenerator Build(Func<CaStatusResponse> status)
    {
        var proxy = DispatchProxy.Create<ICertificateGenerator, StubCertificateGenerator>();
        ((StubCertificateGenerator)(object)proxy)._status = status;
        return proxy;
    }

    protected override object? Invoke(MethodInfo? targetMethod, object?[]? args) =>
        targetMethod?.Name == nameof(ICertificateGenerator.GetCaStatus)
            ? _status()
            : throw new NotSupportedException(targetMethod?.Name);
}

internal static class AttentionAccessFor
{
    public static readonly AttentionAccess Everything = new(CanViewCertificates: true, CanEditSettings: true, IsAdmin: true);
    public static readonly AttentionAccess ViewerOnly = new(CanViewCertificates: true, CanEditSettings: false);
    public static readonly AttentionAccess Nothing = new(CanViewCertificates: false, CanEditSettings: false);
}
