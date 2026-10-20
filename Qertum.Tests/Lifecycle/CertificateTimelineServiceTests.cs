using Qertum.Services;
using Qertum.Services.Lifecycle;

namespace Qertum.Tests.Lifecycle;

public sealed class CertificateTimelineServiceTests
{
    [Fact]
    public async Task AnAcmeIssuedCertificate_IncludesItsOrdersHistoryWithHints_ForSettingsEditOnly()
    {
        var ct = TestContext.Current.CancellationToken;
        var database = SharedInMemoryDatabase.Create(createSchema: true);
        await using var db = database.CreateContext();
        var request = IssuedRequest("acme.example.com", createdAt: T0);
        var account = new Qertum.Services.Acme.AcmeAccount { JwkThumbprint = "t", PublicKeyJwk = "{}" };
        var order = new Qertum.Services.Acme.AcmeOrder
        {
            AccountId = account.Id, IdentifiersJson = """[{"type":"dns","value":"acme.example.com"}]""",
            ExpiresAtUtc = T0.AddDays(7), CertificateRequestId = request.Id
        };
        db.CertificateRequests.Add(request);
        db.AcmeAccounts.Add(account);
        db.AcmeOrders.Add(order);
        db.LifecycleEvents.Add(new LifecycleEvent
        {
            Id = Guid.NewGuid(), Kind = LifecycleEventKinds.Diagnostic, OccurredAtUtc = T0.AddMinutes(-5),
            SubjectType = LifecycleSubjectTypes.AcmeOrder, SubjectId = order.Id,
            Action = DiagnosticActions.ChallengeAttemptFailed, Category = "DnsNoTxtRecord", PerformedBy = "system"
        });
        await db.SaveChangesAsync(ct);
        var service = new CertificateTimelineService(db);

        var admin = (await service.GetAsync(request.Id, Everything, ct))!;
        var viewer = (await service.GetAsync(request.Id, Viewer, ct))!;

        var attempt = Assert.Single(admin.Entries, e => e.Action == DiagnosticActions.ChallengeAttemptFailed);
        Assert.Equal(DiagnosticHints.For("DnsNoTxtRecord"), attempt.Hint);
        Assert.DoesNotContain(viewer.Entries, e => e.Action == DiagnosticActions.ChallengeAttemptFailed);
        Assert.Equal(1, viewer.Withheld.Single(w => w.Section == TimelineSection.Diagnostics).Count);
    }

    private static readonly TimelineAccess Everything = new(CanEditSettings: true, CanSeeKeyExports: true);
    private static readonly TimelineAccess Viewer = new(CanEditSettings: false, CanSeeKeyExports: false);
    private static readonly DateTime T0 = new(2026, 9, 1, 8, 0, 0, DateTimeKind.Utc);

    [Fact]
    public async Task UnknownRequest_ReturnsNull()
    {
        var ct = TestContext.Current.CancellationToken;
        var database = SharedInMemoryDatabase.Create(createSchema: true);
        await using var db = database.CreateContext();

        Assert.Null(await new CertificateTimelineService(db).GetAsync(new CertificateRequestId(Guid.NewGuid()), Everything, ct));
    }

    [Fact]
    public async Task EventsComeOldestFirst_AndRecordMilestonesFillOnlyWhatNoEventCovers()
    {
        var ct = TestContext.Current.CancellationToken;
        var database = SharedInMemoryDatabase.Create(createSchema: true);
        await using var db = database.CreateContext();
        var request = IssuedRequest("web.example.com", createdAt: T0);
        db.CertificateRequests.Add(request);
        db.LifecycleEvents.AddRange(
            AuditEvent(request.Id, "Created", T0),
            AuditEvent(request.Id, "Approved", T0.AddMinutes(5)));
        await db.SaveChangesAsync(ct);

        var timeline = (await new CertificateTimelineService(db).GetAsync(request.Id, Everything, ct))!;

        Assert.Equal(["Created", "Approved", "Issued"], timeline.Entries.Select(e => e.Action));
        Assert.Equal(TimelineEntryKind.Audit, timeline.Entries[0].Kind);
        // No "Issued" event exists, so the issue date comes from the request's own ValidFrom.
        Assert.Equal(TimelineEntryKind.Record, timeline.Entries[2].Kind);
        Assert.Equal(TimelineCompleteness.Full, timeline.Completeness);
    }

    [Fact]
    public async Task ARequestOlderThanTheFirstEvent_IsMarkedPartial()
    {
        var ct = TestContext.Current.CancellationToken;
        var database = SharedInMemoryDatabase.Create(createSchema: true);
        await using var db = database.CreateContext();
        var old = IssuedRequest("old.example.com", createdAt: T0.AddYears(-1));
        var recent = IssuedRequest("new.example.com", createdAt: T0);
        db.CertificateRequests.AddRange(old, recent);
        db.LifecycleEvents.Add(AuditEvent(recent.Id, "Created", T0));
        await db.SaveChangesAsync(ct);

        var timeline = (await new CertificateTimelineService(db).GetAsync(old.Id, Everything, ct))!;

        Assert.Equal(TimelineCompleteness.PartialBeforeUpgrade, timeline.Completeness);
        Assert.All(timeline.Entries, e => Assert.Equal(TimelineEntryKind.Record, e.Kind));
    }

    [Fact]
    public async Task Renewals_AreFollowedBothWaysWithSummariesForTheSideBySideView()
    {
        var ct = TestContext.Current.CancellationToken;
        var database = SharedInMemoryDatabase.Create(createSchema: true);
        await using var db = database.CreateContext();
        var original = IssuedRequest("web.example.com", createdAt: T0);
        var renewal = IssuedRequest("web.example.com", createdAt: T0.AddDays(60), renewedFrom: original.Id);
        var second = IssuedRequest("web.example.com", createdAt: T0.AddDays(120), renewedFrom: renewal.Id);
        db.CertificateRequests.AddRange(original, renewal, second);
        await db.SaveChangesAsync(ct);

        var timeline = (await new CertificateTimelineService(db).GetAsync(renewal.Id, Everything, ct))!;

        var renewals = timeline.Entries.Where(e => e.Kind == TimelineEntryKind.Renewal).ToList();
        Assert.Equal(["RenewedFrom", "RenewedAs"], renewals.Select(e => e.Action));
        Assert.Equal((Guid)original.Id, renewals[0].RelatedRequestId);
        Assert.Equal((Guid)second.Id, renewals[1].RelatedRequestId);
        Assert.Equal(
            new[] { (Guid)original.Id, (Guid)second.Id }.Order(),
            timeline.Related.Select(r => r.Id).Order());
        Assert.Equal((Guid)renewal.Id, timeline.Subject.Id);
    }

    [Fact]
    public async Task AViewer_HasWebhooksKeyExportsAndDiagnosticsWithheldAndCounted()
    {
        var ct = TestContext.Current.CancellationToken;
        var database = SharedInMemoryDatabase.Create(createSchema: true);
        await using var db = database.CreateContext();
        var request = IssuedRequest("web.example.com", createdAt: T0);
        var webhook = new Webhook { Id = new WebhookId(Guid.NewGuid()), Name = "hook", Url = "https://hook.invalid/", EventsJson = "[]", IsEnabled = true };
        db.CertificateRequests.Add(request);
        db.Webhooks.Add(webhook);
        db.WebhookDeliveries.Add(new WebhookDelivery
        {
            Id = Guid.NewGuid(), WebhookId = webhook.Id, EventType = "Issued", ResourceId = request.Id,
            Payload = "{\"secret\":\"never shown\"}", ResolvedUrl = "https://hook.invalid/?q=never",
            Status = "Failed", AttemptCount = 5, LastErrorMessage = "HTTP 500", CreatedAtUtc = T0.AddHours(1)
        });
        db.LifecycleEvents.AddRange(
            AuditEvent(request.Id, "Created", T0),
            AuditEvent(request.Id, "PfxExported", T0.AddHours(2)),
            DiagnosticEvent(request.Id, "ReenrollRefused", T0.AddHours(3)));
        await db.SaveChangesAsync(ct);

        var service = new CertificateTimelineService(db);
        var viewer = (await service.GetAsync(request.Id, Viewer, ct))!;
        var admin = (await service.GetAsync(request.Id, Everything, ct))!;

        Assert.DoesNotContain(viewer.Entries, e => e.Action is "PfxExported" or "ReenrollRefused" || e.Kind == TimelineEntryKind.WebhookDelivery);
        Assert.Equal(
            [(TimelineSection.WebhookDeliveries, 1), (TimelineSection.KeyExports, 1), (TimelineSection.Diagnostics, 1)],
            viewer.Withheld.Select(w => (w.Section, w.Count)));
        Assert.Empty(admin.Withheld);
        var delivery = Assert.Single(admin.Entries, e => e.Kind == TimelineEntryKind.WebhookDelivery);
        Assert.Equal("Failed", delivery.Category);
        Assert.Equal("HTTP 500", delivery.Detail);
        Assert.DoesNotContain(admin.Entries, e => (e.Detail ?? "").Contains("never", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AViewerWithNothingToHide_StillSeesTheSectionsListedAsWithheld()
    {
        // Listing only non-empty sections would let an empty list read as "nothing happened".
        var ct = TestContext.Current.CancellationToken;
        var database = SharedInMemoryDatabase.Create(createSchema: true);
        await using var db = database.CreateContext();
        var request = IssuedRequest("web.example.com", createdAt: T0);
        db.CertificateRequests.Add(request);
        await db.SaveChangesAsync(ct);

        var viewer = (await new CertificateTimelineService(db).GetAsync(request.Id, Viewer, ct))!;

        Assert.Equal(
            [TimelineSection.WebhookDeliveries, TimelineSection.KeyExports, TimelineSection.Diagnostics],
            viewer.Withheld.Select(w => w.Section));
        Assert.All(viewer.Withheld, w => Assert.Equal(0, w.Count));
    }

    private static CertificateRequest IssuedRequest(string cn, DateTime createdAt, CertificateRequestId? renewedFrom = null) => new()
    {
        CommonName = cn, RequestedBy = "alice", Type = "WebServer", Status = CertificateRequestStatus.Issued,
        CreatedAtUtc = createdAt, UpdatedAtUtc = createdAt, ValidFrom = createdAt.AddMinutes(10),
        ValidTo = createdAt.AddDays(90), SerialNumber = Guid.NewGuid().ToString("N"), RenewedFromId = renewedFrom
    };

    private static LifecycleEvent AuditEvent(CertificateRequestId id, string action, DateTime at) => new()
    {
        Id = Guid.NewGuid(), Kind = LifecycleEventKinds.Audit, OccurredAtUtc = at,
        SubjectType = LifecycleSubjectTypes.CertificateRequest, SubjectId = id, Action = action, PerformedBy = "alice"
    };

    private static LifecycleEvent DiagnosticEvent(CertificateRequestId id, string action, DateTime at) => new()
    {
        Id = Guid.NewGuid(), Kind = LifecycleEventKinds.Diagnostic, OccurredAtUtc = at,
        SubjectType = LifecycleSubjectTypes.CertificateRequest, SubjectId = id, Action = action, PerformedBy = "est"
    };
}
