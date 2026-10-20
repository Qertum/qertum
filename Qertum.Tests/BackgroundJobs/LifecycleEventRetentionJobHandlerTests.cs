using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Qertum.QueueConsumer;
using Qertum.Services;
using Qertum.Services.Lifecycle;

namespace Qertum.Tests.BackgroundJobs;

public sealed class LifecycleEventRetentionJobHandlerTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 21, 12, 0, 0, TimeSpan.Zero);

    [Theory]
    [InlineData("Day", 365, 365.0)]
    [InlineData("Hour", 48, 2.0)]
    [InlineData("Month", 12, 372.0)]
    public void AuditWindow_IsTheFileRetention(string interval, int files, double expectedDays)
    {
        var window = AuditRetention.WindowFor(new AuditLogOptions
        {
            File = new AuditLogOptions.FileLogOptions { RollingInterval = interval, RetainedFileCountLimit = files }
        });

        Assert.Equal(TimeSpan.FromDays(expectedDays), window);
    }

    [Fact]
    public void AuditWindow_IsNullWhenFilesAreKeptForever()
    {
        Assert.Null(AuditRetention.WindowFor(new AuditLogOptions
        {
            File = new AuditLogOptions.FileLogOptions { RollingInterval = "Infinite" }
        }));
    }

    [Fact]
    public async Task Sweep_DeletesEachKindPastItsOwnLimitAndKeepsTheRest()
    {
        var ct = TestContext.Current.CancellationToken;
        var database = SharedInMemoryDatabase.Create(createSchema: true);
        await using (var db = database.CreateContext())
        {
            db.LifecycleEvents.AddRange(
                Event(LifecycleEventKinds.Diagnostic, Now.AddDays(-31)),
                Event(LifecycleEventKinds.Diagnostic, Now.AddDays(-29)),
                Event(LifecycleEventKinds.Audit, Now.AddDays(-366)),
                Event(LifecycleEventKinds.Audit, Now.AddDays(-31)));
            await db.SaveChangesAsync(ct);
        }

        await using var context = database.CreateContext();
        var service = new LifecycleEventRetentionJobHandler(
            context,
            Options.Create(new LifecycleEventsOptions { DiagnosticRetentionDays = 30 }),
            Options.Create(new AuditLogOptions()),
            new FakeTimeProvider(Now),
            NullLogger<LifecycleEventRetentionJobHandler>.Instance);

        var (diagnostic, audit) = await service.SweepAsync(ct);

        Assert.Equal((1, 1), (diagnostic, audit));
        await using var check = database.CreateContext();
        Assert.Equal(2, await check.LifecycleEvents.CountAsync(ct));
    }

    private static LifecycleEvent Event(string kind, DateTimeOffset at) => new()
    {
        Id = Guid.NewGuid(), Kind = kind, OccurredAtUtc = at.UtcDateTime,
        SubjectType = LifecycleSubjectTypes.CertificateRequest, SubjectId = Guid.NewGuid(),
        Action = "Created", PerformedBy = "alice"
    };
}
