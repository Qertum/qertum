using Qertum.Services;
using Qertum.Services.Lifecycle;
using Qertum.Tests.Policies;
using static Qertum.Tests.Pqc.PqcReportTestKit;

namespace Qertum.Tests.Pqc;

public sealed class PqcMigrationReportObservedTests
{
    private static LifecycleEvent Event(CertificateRequestId request, string action, string by, DateTime at) => new()
    {
        Id = Guid.NewGuid(), Kind = LifecycleEventKinds.Diagnostic, SubjectType = LifecycleSubjectTypes.CertificateRequest,
        SubjectId = request, Action = action, PerformedBy = by, OccurredAtUtc = at, Category = DiagnosticCategories.PqcStage
    };

    private static async Task<PqcObservedTraffic> ObservedAsync(PolicyTestDb scope, PqcReportQuery? query = null,
        int retentionDays = 30, CancellationToken ct = default) =>
        (await Service(scope.Db, Clock(), retentionDays).BuildAsync(query ?? new PqcReportQuery(), WithObserved, ct)).Observed!;

    private static async Task<(CertificateRequest Web, CertificateRequest Acme, CertificateRequest Est, CertificateRequest EstCert)> SeedAsync(
        PolicyTestDb scope, CancellationToken ct)
    {
        var rest = Row("rest.corp.example", CertificateKeyAlgorithm.Rsa, CertificateRequestStatus.Pending, subject: "alice-sub");
        var acme = Row("acme.corp.example", CertificateKeyAlgorithm.Rsa, CertificateRequestStatus.Pending, subject: "acme:42");
        var est = Row("est.corp.example", CertificateKeyAlgorithm.Rsa, CertificateRequestStatus.Pending, subject: "est:credential-1", type: "ClientAuth");
        var estCert = Row("estcert.corp.example", CertificateKeyAlgorithm.Rsa, CertificateRequestStatus.Pending, subject: "est-cert:0A1B");
        scope.Db.CertificateRequests.AddRange(rest, acme, est, estCert);
        await scope.Db.SaveChangesAsync(ct);
        return (rest, acme, est, estCert);
    }

    [Fact]
    public async Task CountsPerTemplateSourceAndKind_WithDistinctIdentities()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var (rest, acme, est, estCert) = await SeedAsync(scope, ct);
        var at = Now.AddDays(-2);
        scope.Db.LifecycleEvents.AddRange(
            Event(rest.Id, PqcEventActions.Warned, "alice", at), Event(rest.Id, PqcEventActions.Warned, "alice", at),
            Event(rest.Id, PqcEventActions.Warned, "bob", at),
            Event(acme.Id, PqcEventActions.Observed, "acme:42", at),
            Event(est.Id, PqcEventActions.ExceptionApplied, "est:credential-1", at),
            Event(estCert.Id, PqcEventActions.Observed, "est-cert:0A1B", at));
        await scope.Db.SaveChangesAsync(ct);

        var observed = await ObservedAsync(scope, ct: ct);

        Assert.Equal(6, observed.TotalEvents);
        Assert.Equal(5, observed.DistinctIdentities);   // alice, bob, acme:42, est:credential-1, est-cert:0A1B
        var warned = Assert.Single(observed.Counts, c => c is { Source: "rest", Kind: "Warned" });
        Assert.Equal(("WebServer", 3, 2), (warned.TemplateTypeKey, warned.Count, warned.DistinctIdentities));
        Assert.Equal(1, Assert.Single(observed.Counts, c => c is { Source: "acme", Kind: "Observed" }).Count);
        Assert.Equal("ClientAuth", Assert.Single(observed.Counts, c => c is { Source: "est", Kind: "ExceptionApplied" }).TemplateTypeKey);
        Assert.Equal(1, Assert.Single(observed.Counts, c => c is { Source: "est-cert", Kind: "Observed" }).Count);
    }

    [Fact]
    public async Task TheWindow_IsClampedToRetention_AndOlderEventsAreLeftOut()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var (rest, _, _, _) = await SeedAsync(scope, ct);
        scope.Db.LifecycleEvents.AddRange(
            Event(rest.Id, PqcEventActions.Warned, "alice", Now.AddDays(-10)),
            Event(rest.Id, PqcEventActions.Warned, "alice", Now.AddDays(-40)));
        await scope.Db.SaveChangesAsync(ct);

        var wide = await ObservedAsync(scope, new PqcReportQuery { ObservedDays = 90 }, retentionDays: 30, ct: ct);
        var narrow = await ObservedAsync(scope, new PqcReportQuery { ObservedDays = 7 }, retentionDays: 30, ct: ct);

        Assert.Equal((90, 30, 30, 1), (wide.RequestedDays, wide.EffectiveDays, wide.RetentionDays, wide.TotalEvents));
        Assert.Equal(Now.AddDays(-30), wide.SinceUtc);
        Assert.Equal((7, 7, 0), (narrow.RequestedDays, narrow.EffectiveDays, narrow.TotalEvents));
    }

    [Fact]
    public async Task OtherActionsAndOtherSubjects_AreNotCounted()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var (rest, _, _, _) = await SeedAsync(scope, ct);
        scope.Db.LifecycleEvents.AddRange(
            Event(rest.Id, "Approved", "alice", Now.AddDays(-1)),
            new LifecycleEvent
            {
                Id = Guid.NewGuid(), Kind = LifecycleEventKinds.Diagnostic, SubjectType = LifecycleSubjectTypes.AcmeOrder,
                SubjectId = rest.Id, Action = PqcEventActions.Warned, PerformedBy = "x", OccurredAtUtc = Now.AddDays(-1)
            },
            new LifecycleEvent
            {
                Id = Guid.NewGuid(), Kind = LifecycleEventKinds.Audit,
                SubjectType = LifecycleSubjectTypes.CertificateRequest, SubjectId = rest.Id, Action = PqcEventActions.Warned,
                PerformedBy = "x", OccurredAtUtc = Now.AddDays(-1)
            });
        await scope.Db.SaveChangesAsync(ct);

        Assert.Equal(0, (await ObservedAsync(scope, ct: ct)).TotalEvents);
    }

    [Fact]
    public async Task EventsWhoseRequestRowIsGone_CountUnderUnknown_NotDropped()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        scope.Db.LifecycleEvents.Add(Event(new CertificateRequestId(Guid.NewGuid()), PqcEventActions.Warned, "alice", Now.AddDays(-1)));
        await scope.Db.SaveChangesAsync(ct);

        var observed = await ObservedAsync(scope, ct: ct);

        var count = Assert.Single(observed.Counts);
        Assert.Equal(("unknown", "unknown", "Warned", 1), (count.TemplateTypeKey, count.Source, count.Kind, count.Count));
    }

    [Fact]
    public async Task ATemplateFilter_LimitsTheEvents_AndLeavesOutTheUnattributable()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var (rest, _, est, _) = await SeedAsync(scope, ct);
        scope.Db.LifecycleEvents.AddRange(
            Event(rest.Id, PqcEventActions.Warned, "alice", Now.AddDays(-1)),
            Event(est.Id, PqcEventActions.Warned, "est:credential-1", Now.AddDays(-1)),
            Event(new CertificateRequestId(Guid.NewGuid()), PqcEventActions.Warned, "ghost", Now.AddDays(-1)));
        await scope.Db.SaveChangesAsync(ct);

        var observed = await ObservedAsync(scope, new PqcReportQuery { TemplateTypeKey = "ClientAuth" }, ct: ct);

        Assert.Equal(1, observed.TotalEvents);
        Assert.Equal("ClientAuth", Assert.Single(observed.Counts).TemplateTypeKey);
    }

    [Fact]
    public async Task WithoutSettingsEdit_TheBlockIsAbsentAndWithheldIsNamedEvenAtZeroEvents()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);

        var viewer = await Service(scope.Db, Clock()).BuildAsync(new PqcReportQuery(), ViewOnly, ct);
        var editor = await Service(scope.Db, Clock()).BuildAsync(new PqcReportQuery(), WithObserved, ct);

        Assert.Null(viewer.Observed);
        Assert.Equal(["observed"], viewer.Withheld);
        Assert.NotNull(editor.Observed);
        Assert.Equal(0, editor.Observed!.TotalEvents);
        Assert.Empty(editor.Withheld);
    }

    [Fact]
    public async Task AViewer_NeverSeesTheEventData()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var (rest, _, _, _) = await SeedAsync(scope, ct);
        scope.Db.LifecycleEvents.Add(Event(rest.Id, PqcEventActions.Warned, "alice", Now.AddDays(-1)));
        await scope.Db.SaveChangesAsync(ct);

        var viewer = await Service(scope.Db, Clock()).BuildAsync(new PqcReportQuery(), ViewOnly, ct);

        Assert.Null(viewer.Observed);
        Assert.DoesNotContain("alice", System.Text.Json.JsonSerializer.Serialize(viewer), StringComparison.Ordinal);
    }
}
