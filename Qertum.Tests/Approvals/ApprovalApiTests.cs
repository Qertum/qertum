using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Qertum.Services;
using Qertum.Services.Approvals;
using Qertum.Services.Auth;
using Qertum.Services.Lifecycle;
using Qertum.Tests.BulkOperations;
using Qertum.Tests.Issuers;

namespace Qertum.Tests.Approvals;

public sealed class ApprovalApiTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private sealed class Recorders
    {
        public RecordingAudit Audit { get; } = new();
        public RecordingWebhooks Webhooks { get; } = new();
    }

    private static IssuerApiHost Host(Recorders recorders) => new(services =>
    {
        services.RemoveAll<IAuditLogService>();
        services.AddSingleton<IAuditLogService>(recorders.Audit);
        services.RemoveAll<IWebhookService>();
        services.AddSingleton<IWebhookService>(recorders.Webhooks);
    });

    private static async Task<JsonElement> JsonOf(HttpResponseMessage response) =>
        await response.Content.ReadFromJsonAsync<JsonElement>(Ct);

    private static async Task<(HttpResponseMessage Response, JsonElement Body)> RequestAsync(
        HttpClient client, string operation, string? target, string? note = "because")
    {
        var response = await client.PostAsJsonAsync("/v1/approvals", new { operation, targetId = target, note }, Ct);
        return (response, response.IsSuccessStatusCode ? await JsonOf(response) : default);
    }

    private static async Task<string> IssuerIdAsync(IssuerApiHost host)
    {
        host.Kit.InitializeLegacy();
        return (await host.DefaultIssuerIdAsync(Ct)).ToString();
    }

    // ── request ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Request_Returns201_Audits_AndEnqueuesAWebhookWithoutTheNote()
    {
        var rec = new Recorders();
        await using var host = Host(rec);

        var (response, body) = await RequestAsync(host.Sub("sub-alice"), ApprovalOperations.IssuerRetire, await IssuerIdAsync(host), note: "SECRET-NOTE-TEXT");

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Equal("Pending", body.GetProperty("status").GetString());
        Assert.Equal("SECRET-NOTE-TEXT", body.GetProperty("note").GetString());
        var audit = Assert.Single(rec.Audit.Entries, e => e.Action == "ApprovalRequested");
        Assert.Equal("sub-alice", audit.PerformedBy);
        var hook = Assert.Single(rec.Webhooks.Events, e => e.EventType == "ApprovalRequested");
        Assert.DoesNotContain("SECRET-NOTE-TEXT", audit.Detail ?? "", StringComparison.Ordinal);
        Assert.DoesNotContain(hook.Fields!.Values, v => v?.Contains("SECRET-NOTE-TEXT", StringComparison.Ordinal) == true);
        Assert.Equal(ApprovalOperations.IssuerRetire, hook.Fields!["operation"]);
    }

    [Fact]
    public async Task Request_ForAMissingTarget_Is404_AndWritesNothing()
    {
        var rec = new Recorders();
        await using var host = Host(rec);

        var (response, _) = await RequestAsync(host.Sub("sub-alice"), ApprovalOperations.IssuerRetire, Guid.NewGuid().ToString());

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.DoesNotContain(rec.Audit.Entries, e => e.Action.StartsWith("Approval", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Request_ByACallerWhoMayNotPerformTheOperation_Is403_AndWritesNothing()
    {
        var rec = new Recorders();
        await using var host = Host(rec);

        var (retire, _) = await RequestAsync(host.Sub("sub-user", "nobody"), ApprovalOperations.IssuerRetire, await IssuerIdAsync(host));
        var (publish, _) = await RequestAsync(host.Sub("sub-user", "nobody"), ApprovalOperations.PolicyPublish, Guid.NewGuid().ToString());

        Assert.Equal(HttpStatusCode.Forbidden, retire.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, publish.StatusCode);
        Assert.DoesNotContain(rec.Audit.Entries, e => e.Action.StartsWith("Approval", StringComparison.Ordinal));
        await using var db = host.Kit.Database.CreateContext();
        Assert.False(await db.ApprovalRequests.AnyAsync(Ct));
    }

    [Fact]
    public async Task Request_WithoutASubject_Is403()
    {
        await using var host = Host(new Recorders());

        var (response, _) = await RequestAsync(host.Admin(), ApprovalOperations.IssuerRetire, await IssuerIdAsync(host));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Request_ForAnUnknownOperation_Is400_AndASecondOpenOneIs409()
    {
        await using var host = Host(new Recorders());
        var alice = host.Sub("sub-alice");
        var issuer = await IssuerIdAsync(host);

        Assert.Equal(HttpStatusCode.BadRequest, (await RequestAsync(alice, "make-coffee", issuer)).Response.StatusCode);
        Assert.Equal(HttpStatusCode.Created, (await RequestAsync(alice, ApprovalOperations.IssuerRetire, issuer)).Response.StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await RequestAsync(alice, ApprovalOperations.IssuerRetire, issuer)).Response.StatusCode);
    }

    // ── decide ─────────────────────────────────────────────────────────────────

    private static async Task<string> FiledAsync(IssuerApiHost host, string by = "sub-alice")
    {
        var (_, body) = await RequestAsync(host.Sub(by), ApprovalOperations.IssuerRetire, await IssuerIdAsync(host));
        return body.GetProperty("id").GetString()!;
    }

    [Fact]
    public async Task Approve_ByAnotherAdmin_Returns200WithTheGrantWindow_AuditsAndAnnounces()
    {
        var rec = new Recorders();
        await using var host = Host(rec);
        var id = await FiledAsync(host);

        var response = await host.Sub("sub-bob").PostAsJsonAsync($"/v1/approvals/{id}/approve", new { note = "ok" }, Ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await JsonOf(response);
        Assert.Equal("Approved", body.GetProperty("status").GetString());
        Assert.True(body.GetProperty("grantExpiresAtUtc").GetDateTime() > DateTime.UtcNow.AddMinutes(10));
        Assert.Contains(rec.Audit.Entries, e => e.Action == "ApprovalApproved" && e.PerformedBy == "sub-bob");
        Assert.Contains(rec.Webhooks.Events, e => e.EventType == "ApprovalApproved");
    }

    [Fact]
    public async Task Approve_ByTheRequester_ByANonAdmin_OrWithoutASubject_Is403()
    {
        await using var host = Host(new Recorders());
        var id = await FiledAsync(host);

        Assert.Equal(HttpStatusCode.Forbidden, (await host.Sub("sub-alice").PostAsJsonAsync($"/v1/approvals/{id}/approve", new { }, Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await host.Sub("sub-user", "nobody").PostAsJsonAsync($"/v1/approvals/{id}/approve", new { }, Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await host.Admin().PostAsJsonAsync($"/v1/approvals/{id}/approve", new { }, Ct)).StatusCode);
    }

    [Fact]
    public async Task Approve_Twice_TheSecondIs409_AndAnUnknownIdIs404()
    {
        await using var host = Host(new Recorders());
        var id = await FiledAsync(host);

        Assert.Equal(HttpStatusCode.OK, (await host.Sub("sub-bob").PostAsJsonAsync($"/v1/approvals/{id}/approve", new { }, Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await host.Sub("sub-carol").PostAsJsonAsync($"/v1/approvals/{id}/approve", new { }, Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await host.Sub("sub-bob").PostAsJsonAsync($"/v1/approvals/{Guid.NewGuid()}/approve", new { }, Ct)).StatusCode);
    }

    [Fact]
    public async Task Deny_RecordsTheNote_AuditsAndAnnounces()
    {
        var rec = new Recorders();
        await using var host = Host(rec);
        var id = await FiledAsync(host);

        var response = await host.Sub("sub-bob").PostAsJsonAsync($"/v1/approvals/{id}/deny", new { note = "not now" }, Ct);

        var body = await JsonOf(response);
        Assert.Equal("Denied", body.GetProperty("status").GetString());
        Assert.Equal("not now", body.GetProperty("decisionNote").GetString());
        Assert.Contains(rec.Audit.Entries, e => e.Action == "ApprovalDenied");
        Assert.Contains(rec.Webhooks.Events, e => e.EventType == "ApprovalDenied");
    }

    [Fact]
    public async Task UsingAGrant_IsAuditedAndAnnounced_OnceTheOperationSucceeded()
    {
        var rec = new Recorders();
        await using var host = Host(rec);
        await using (var settingsDb = host.Kit.Database.CreateContext())
            await settingsDb.Settings.ExecuteUpdateAsync(s => s.SetProperty(x => x.RequireTwoPersonApproval, true), Ct);
        Guid requestId;
        using (var scope = host.Factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            var request = new CertificateRequest
            {
                CommonName = $"{Guid.NewGuid():N}.example", RequestedBy = "owner", RequestedBySubject = "sub-owner",
                Status = CertificateRequestStatus.Issued, CertificatePem = "pem", PrivateKeyPem = "key"
            };
            db.CertificateRequests.Add(request);
            db.ApprovalRequests.Add(new ApprovalRequest
            {
                Operation = ApprovalOperations.KeyExport, TargetId = request.Id.ToString(), RequestedBySubject = "sub-alice",
                RequestedByName = "sub-alice", RequestedAtUtc = DateTime.UtcNow, Status = ApprovalStatus.Approved,
                DecidedBySubject = "sub-bob", DecidedByName = "sub-bob", GrantExpiresAtUtc = DateTime.UtcNow.AddMinutes(10)
            });
            await db.SaveChangesAsync(Ct);
            requestId = request.Id;
        }

        var response = await host.Sub("sub-alice").GetAsync($"/v1/certificate-requests/{requestId}/private-key?pqc=false", Ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var actions = rec.Audit.Entries.Select(e => e.Action).ToList();
        Assert.Single(actions, a => a == "ApprovalUsed");
        Assert.True(actions.IndexOf("PrivateKeyDownloaded") >= 0 && actions.IndexOf("PrivateKeyDownloaded") < actions.IndexOf("ApprovalUsed"));
        Assert.Contains(rec.Webhooks.Events, e => e.EventType == "ApprovalUsed");
    }

    [Fact]
    public async Task AnApprovalAskedForWithAnUppercaseId_StillCoversTheOperationOnItsLowercaseUrl()
    {
        await using var host = Host(new Recorders());
        await using (var settingsDb = host.Kit.Database.CreateContext())
            await settingsDb.Settings.ExecuteUpdateAsync(s => s.SetProperty(x => x.RequireTwoPersonApproval, true), Ct);
        var issuer = await IssuerIdAsync(host);
        var (_, filed) = await RequestAsync(host.Sub("sub-alice"), ApprovalOperations.IssuerRetire, issuer.ToUpperInvariant());
        await host.Sub("sub-bob").PostAsJsonAsync($"/v1/approvals/{filed.GetProperty("id").GetString()}/approve", new { }, Ct);

        var response = await host.Sub("sub-alice").PostAsJsonAsync($"/v1/issuers/{issuer}/retire", new { }, Ct);

        Assert.DoesNotContain("Approval required", await response.Content.ReadAsStringAsync(Ct), StringComparison.Ordinal);
    }

    [Fact]
    public async Task AGrantReleasedAfterAFailingOperation_IsNotReportedAsUsed()
    {
        var rec = new Recorders();
        await using var host = Host(rec);
        await using (var settingsDb = host.Kit.Database.CreateContext())
            await settingsDb.Settings.ExecuteUpdateAsync(s => s.SetProperty(x => x.RequireTwoPersonApproval, true), Ct);
        var unknownIssuer = Guid.NewGuid().ToString();
        ApprovalRequestId grant;
        await using (var db = host.Kit.Database.CreateContext())
        {
            var row = new ApprovalRequest
            {
                Operation = ApprovalOperations.IssuerRetire, TargetId = unknownIssuer, RequestedBySubject = "sub-alice", RequestedByName = "sub-alice",
                RequestedAtUtc = DateTime.UtcNow, Status = ApprovalStatus.Approved, GrantExpiresAtUtc = DateTime.UtcNow.AddMinutes(10)
            };
            db.ApprovalRequests.Add(row);
            await db.SaveChangesAsync(Ct);
            grant = row.Id;
        }

        var response = await host.Sub("sub-alice").PostAsJsonAsync($"/v1/issuers/{unknownIssuer}/retire", new { }, Ct);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.DoesNotContain(rec.Audit.Entries, e => e.Action == "ApprovalUsed");
        Assert.DoesNotContain(rec.Webhooks.Events, e => e.EventType == "ApprovalUsed");
        await using var check = host.Kit.Database.CreateContext();
        Assert.Equal(ApprovalStatus.Approved, (await check.ApprovalRequests.AsNoTracking().FirstAsync(a => a.Id == grant, Ct)).Status);
    }

    // ── read ───────────────────────────────────────────────────────────────────

    [Fact]
    public async Task List_AnAdminSeesAll_AUserSeesOnlyTheirOwn_AndGetIsScopedTheSame()
    {
        await using var host = Host(new Recorders());
        var id = await FiledAsync(host);

        var all = await JsonOf(await host.Sub("sub-bob").GetAsync("/v1/approvals", Ct));
        var mine = await JsonOf(await host.Sub("sub-bob").GetAsync("/v1/approvals?mine=true", Ct));
        var other = await JsonOf(await host.Sub("sub-user", "nobody").GetAsync("/v1/approvals", Ct));

        Assert.Equal(1, all.GetProperty("totalCount").GetInt32());
        Assert.Equal(0, mine.GetProperty("totalCount").GetInt32());
        Assert.Equal(0, other.GetProperty("totalCount").GetInt32());
        Assert.Equal(HttpStatusCode.OK, (await host.Sub("sub-alice").GetAsync($"/v1/approvals/{id}", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await host.Sub("sub-user", "nobody").GetAsync($"/v1/approvals/{id}", Ct)).StatusCode);
    }

    // ── the flag ───────────────────────────────────────────────────────────────

    [Fact]
    public async Task Flag_AdminOnly_Audited_AndAnnounced()
    {
        var rec = new Recorders();
        await using var host = Host(rec);

        Assert.Equal(HttpStatusCode.Forbidden, (await host.Sub("sub-user", "nobody").PutAsJsonAsync("/v1/settings/two-person-approval", new { enabled = true }, Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await host.Sub("sub-alice").PutAsJsonAsync("/v1/settings/two-person-approval", new { }, Ct)).StatusCode);
        var response = await host.Sub("sub-alice").PutAsJsonAsync("/v1/settings/two-person-approval", new { enabled = true }, Ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains(rec.Audit.Entries, e => e.Action == "TwoPersonApprovalChanged");
        Assert.Contains(rec.Webhooks.Events, e => e.EventType == "TwoPersonApprovalChanged");
        await using var db = host.Kit.Database.CreateContext();
        Assert.True(await db.Settings.Select(s => s.RequireTwoPersonApproval).SingleAsync(Ct));

        // No change writes nothing more.
        var before = rec.Audit.Entries.Count;
        await host.Sub("sub-alice").PutAsJsonAsync("/v1/settings/two-person-approval", new { enabled = true }, Ct);
        Assert.Equal(before, rec.Audit.Entries.Count);
    }

    [Fact]
    public async Task AGeneralSettingsSave_CannotSwitchTheFlag()
    {
        await using var host = Host(new Recorders());
        var settings = await host.Sub("sub-alice").GetFromJsonAsync<JsonElement>("/v1/settings", Ct);
        var edited = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(settings.GetRawText())!;
        edited["requireTwoPersonApproval"] = JsonSerializer.SerializeToElement(true);

        await host.Sub("sub-alice").PutAsJsonAsync("/v1/settings", edited, Ct);

        await using var db = host.Kit.Database.CreateContext();
        Assert.False(await db.Settings.Select(s => s.RequireTwoPersonApproval).SingleAsync(Ct));
    }

    [Fact]
    public void TheDecisionsAndTheFlag_AreOnTheStepUpTable()
    {
        Assert.True(StepUpRoutes.IsProtected("POST", "/v1/approvals/{id:guid}/approve"));
        Assert.True(StepUpRoutes.IsProtected("POST", "/v1/approvals/{id:guid}/deny"));
        Assert.True(StepUpRoutes.IsProtected("PUT", "/v1/settings/two-person-approval"));
    }

    // ── the catalogs ───────────────────────────────────────────────────────────

    [Fact]
    public void TheApprovalEvents_FormTheirOwnFamily_WithTheDocumentedFields()
    {
        foreach (var name in new[] { "ApprovalRequested", "ApprovalApproved", "ApprovalDenied", "ApprovalUsed", "ApprovalExpired" })
        {
            Assert.Equal(WebhookEventFamily.Approval, WellKnownWebhookEvents.FamilyOf(name));
            Assert.True(AuditActionSubjects.IsKnown(name));
        }

        Assert.True(AuditActionSubjects.IsKnown("TwoPersonApprovalChanged"));
        Assert.Equal(WebhookEventFamily.Settings, WellKnownWebhookEvents.FamilyOf("TwoPersonApprovalChanged"));
        foreach (var field in new[] { "approvalId", "operation", "targetId", "requestedBy", "decidedBy", "status", "grantExpiresAtUtc" })
            Assert.True(WebhookEventFields.IsKnown(WebhookEventFamily.Approval, field), field);
        Assert.False(WebhookEventFields.IsKnown(WebhookEventFamily.Approval, "note"));
    }
}
