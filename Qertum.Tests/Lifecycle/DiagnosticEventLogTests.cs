using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Time.Testing;
using Qertum.Services.Lifecycle;

namespace Qertum.Tests.Lifecycle;

public sealed class DiagnosticEventLogTests
{
    [Fact]
    public async Task ADiagnosticEvent_ReachesTheTableAndNeverTheAuditFile()
    {
        var ct = TestContext.Current.CancellationToken;
        using var harness = new AuditLogHarness();
        var orderId = Guid.NewGuid();

        harness.Service.Record(LifecycleSubjectTypes.AcmeOrder, orderId, "ChallengeAttemptFailed", "acme:1",
            category: "DnsNoTxtRecord", detail: "No TXT record", data: new { attempt = 2 });
        harness.Flush();

        Assert.Empty(harness.AuditFileLines());
        await using var db = harness.Database.CreateContext();
        var row = await db.LifecycleEvents.SingleAsync(ct);
        Assert.Equal(LifecycleEventKinds.Diagnostic, row.Kind);
        Assert.Equal(LifecycleSubjectTypes.AcmeOrder, row.SubjectType);
        Assert.Equal(orderId, row.SubjectId);
        Assert.Equal("DnsNoTxtRecord", row.Category);
        Assert.Equal("acme:1", row.PerformedBy);
        Assert.Equal("""{"attempt":2}""", row.DataJson);
    }

    [Fact]
    public async Task MoreThanTwentyEventsInAMinute_WritesOneSuppressedMarkerAndDropsTheRest()
    {
        var ct = TestContext.Current.CancellationToken;
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 9, 21, 12, 0, 0, TimeSpan.Zero));
        using var harness = new AuditLogHarness(clock);
        var credentialId = Guid.NewGuid();

        for (var i = 0; i < 30; i++)
            harness.Service.Record(LifecycleSubjectTypes.EstCredential, credentialId, "AuthRefused", "est", "WrongPassword");
        harness.Flush();

        await using var db = harness.Database.CreateContext();
        var actions = await db.LifecycleEvents.Select(e => e.Action).ToListAsync(ct);
        Assert.Equal(21, actions.Count);
        Assert.Equal(1, actions.Count(a => a == "EventsSuppressed"));
    }

    [Fact]
    public void TheWindowResetsAfterAMinute()
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 9, 21, 12, 0, 0, TimeSpan.Zero));
        var limiter = new DiagnosticFloodLimiter(clock, perMinute: 2);
        var id = Guid.NewGuid();

        Assert.Equal(FloodAdmission.Admitted, limiter.Admit("EstCredential", id));
        Assert.Equal(FloodAdmission.Admitted, limiter.Admit("EstCredential", id));
        Assert.Equal(FloodAdmission.SuppressedMarker, limiter.Admit("EstCredential", id));
        Assert.Equal(FloodAdmission.Dropped, limiter.Admit("EstCredential", id));
        // Another subject has its own window.
        Assert.Equal(FloodAdmission.Admitted, limiter.Admit("EstCredential", Guid.NewGuid()));

        clock.Advance(TimeSpan.FromMinutes(1));
        Assert.Equal(FloodAdmission.Admitted, limiter.Admit("EstCredential", id));
    }
}
