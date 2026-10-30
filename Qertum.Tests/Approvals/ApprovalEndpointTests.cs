using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Time.Testing;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Services.Approvals;
using Qertum.Services.Auth;
using Qertum.Tests.Issuers;

namespace Qertum.Tests.Approvals;

public sealed class ApprovalEndpointTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static async Task<IssuerApiHost> HostAsync(bool flag = true, Action<IServiceCollection>? configure = null)
    {
        var host = new IssuerApiHost(configure);
        await using var db = host.Kit.Database.CreateContext();
        await db.Settings.ExecuteUpdateAsync(s => s.SetProperty(x => x.RequireTwoPersonApproval, flag), Ct);
        return host;
    }

    private static async Task<Guid> SeedRequestAsync(IssuerApiHost host, string? ownerSubject)
    {
        // Through the host's own context: the key column is encrypted with the host's key ring.
        using var scope = host.Factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        var request = new CertificateRequest
        {
            CommonName = $"{Guid.NewGuid():N}.example", RequestedBy = "owner", RequestedBySubject = ownerSubject, Status = CertificateRequestStatus.Issued,
            CertificatePem = "pem", PrivateKeyPem = "key"
        };
        db.CertificateRequests.Add(request);
        await db.SaveChangesAsync(Ct);
        return request.Id;
    }

    private static async Task<Guid> SeedBulkAsync(IssuerApiHost host, BulkOperationKind kind)
    {
        await using var db = host.Kit.Database.CreateContext();
        var operation = new BulkOperation { Kind = kind, CreatedBy = "someone", CreatedBySubject = "sub-someone", CreatedAtUtc = DateTime.UtcNow };
        db.BulkOperations.Add(operation);
        await db.SaveChangesAsync(Ct);
        return operation.Id;
    }

    private static async Task<ApprovalRequestId> SeedGrantAsync(IssuerApiHost host, string subject, string operation, string? target, int minutes = 15)
    {
        await using var db = host.Kit.Database.CreateContext();
        var grant = new ApprovalRequest
        {
            Operation = operation, TargetId = target, RequestedBySubject = subject, RequestedByName = subject,
            RequestedAtUtc = DateTime.UtcNow.AddMinutes(-1), Status = ApprovalStatus.Approved,
            DecidedBySubject = "sub-other", DecidedByName = "other", DecidedAtUtc = DateTime.UtcNow,
            GrantExpiresAtUtc = DateTime.UtcNow.AddMinutes(minutes)
        };
        db.ApprovalRequests.Add(grant);
        await db.SaveChangesAsync(Ct);
        return grant.Id;
    }

    private static async Task<ApprovalStatus> StatusOfAsync(IssuerApiHost host, ApprovalRequestId id)
    {
        await using var db = host.Kit.Database.CreateContext();
        return (await db.ApprovalRequests.AsNoTracking().FirstAsync(a => a.Id == id, Ct)).Status;
    }

    /// <summary>The target a gated entry acts on, seeding what the gate needs to see.</summary>
    private static async Task<string?> TargetAsync(IssuerApiHost host, ApprovalRouteEntry entry) => entry.Gate switch
    {
        ApprovalGate.NonOwnerKeyAccess => (await SeedRequestAsync(host, "sub-owner")).ToString(),
        ApprovalGate.BulkRevokeOnly => (await SeedBulkAsync(host, BulkOperationKind.Revoke)).ToString(),
        _ => entry.Operation == ApprovalOperations.IssuerCreateIntermediate ? null : Guid.NewGuid().ToString()
    };

    private static HttpRequestMessage Send(ApprovalRouteEntry entry, string? target)
    {
        var url = target is null ? entry.Pattern : entry.Pattern.Replace("{id:guid}", target);
        if (entry.Operation == ApprovalOperations.KeyExport)
            url += "?pqc=false";   // the route declares the flag as required
        return new HttpRequestMessage(new HttpMethod(entry.Method), url)
        {
            Content = entry.Method is "GET" or "DELETE" ? null : new StringContent("{}", Encoding.UTF8, "application/json")
        };
    }

    private static async Task<bool> IsApprovalRefusalAsync(HttpResponseMessage response) =>
        response.StatusCode == HttpStatusCode.Forbidden
        && (await response.Content.ReadAsStringAsync(Ct)).Contains("Approval required", StringComparison.Ordinal);

    // ── the table ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task EveryEntry_IsARealEndpoint_ExactlyOnce_AndStepUpProtected()
    {
        await using var host = await HostAsync();
        var endpoints = host.Factory.Services.GetRequiredService<EndpointDataSource>().Endpoints.OfType<RouteEndpoint>().ToList();

        Assert.Equal(14, ApprovalRoutes.Gated.Count);
        foreach (var entry in ApprovalRoutes.Gated)
        {
            var matches = endpoints.Count(e => e.RoutePattern.RawText == entry.Pattern
                && (e.Metadata.GetMetadata<IHttpMethodMetadata>()?.HttpMethods.Contains(entry.Method, StringComparer.OrdinalIgnoreCase) ?? false));
            Assert.True(matches == 1, $"{entry.Method} {entry.Pattern} matches {matches} endpoints; fix ApprovalRoutes");
            Assert.True(StepUpRoutes.IsProtected(entry.Method, entry.Pattern), $"{entry.Method} {entry.Pattern} is not on the step-up table");
            Assert.True(ApprovalOperations.IsKnown(entry.Operation));
        }
    }

    // ── refusal and grants, every operation ────────────────────────────────────

    [Fact]
    public async Task EveryGatedOperation_IsRefusedWithoutAGrant_AndLetThroughWithOne()
    {
        await using var host = await HostAsync();
        var alice = host.Sub("sub-alice");

        foreach (var entry in ApprovalRoutes.Gated)
        {
            var target = await TargetAsync(host, entry);

            var refused = await alice.SendAsync(Send(entry, target), Ct);
            Assert.True(await IsApprovalRefusalAsync(refused), $"{entry.Operation} without a grant answered {(int)refused.StatusCode}");
            Assert.Contains(entry.Operation, await refused.Content.ReadAsStringAsync(Ct), StringComparison.Ordinal);

            var grant = await SeedGrantAsync(host, "sub-alice", entry.Operation, target);
            var allowed = await alice.SendAsync(Send(entry, target), Ct);
            Assert.False(await IsApprovalRefusalAsync(allowed), $"{entry.Operation} with a grant was still refused");
            // Used when the handler succeeded; given back when it answered an error (a random target is a 404).
            var expected = (int)allowed.StatusCode >= 400 ? ApprovalStatus.Approved : ApprovalStatus.Used;
            Assert.Equal(expected, await StatusOfAsync(host, grant));
        }
    }

    [Fact]
    public async Task AGrantIsUsedOnce_WhenTheHandlerSucceeds()
    {
        await using var host = await HostAsync();
        var id = (await SeedRequestAsync(host, "sub-owner")).ToString();
        var entry = ApprovalRoutes.Gated.First(e => e.Operation == ApprovalOperations.KeyExport);
        var grant = await SeedGrantAsync(host, "sub-alice", entry.Operation, id);
        var alice = host.Sub("sub-alice");

        var first = await alice.SendAsync(Send(entry, id), Ct);
        var second = await alice.SendAsync(Send(entry, id), Ct);

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(ApprovalStatus.Used, await StatusOfAsync(host, grant));
        Assert.True(await IsApprovalRefusalAsync(second));
    }

    [Fact]
    public async Task AGrantIsBoundToItsTarget_ItsCaller_AndItsWindow()
    {
        await using var host = await HostAsync();
        var entry = ApprovalRoutes.Gated.First(e => e.Operation == ApprovalOperations.IssuerRetire);
        var target = Guid.NewGuid().ToString();
        await SeedGrantAsync(host, "sub-alice", entry.Operation, Guid.NewGuid().ToString());   // other target
        await SeedGrantAsync(host, "sub-bob", entry.Operation, target);                         // other caller
        await SeedGrantAsync(host, "sub-alice", entry.Operation, target, minutes: -1);          // expired

        var response = await host.Sub("sub-alice").SendAsync(Send(entry, target), Ct);

        Assert.True(await IsApprovalRefusalAsync(response));
    }

    [Fact]
    public async Task ATokenWithoutASubject_IsRefused()
    {
        await using var host = await HostAsync();
        var entry = ApprovalRoutes.Gated.First(e => e.Operation == ApprovalOperations.IssuerRetire);

        var response = await host.Admin().SendAsync(Send(entry, Guid.NewGuid().ToString()), Ct);

        Assert.True(await IsApprovalRefusalAsync(response));
    }

    [Fact]
    public async Task WithTheFlagOff_NothingIsGated()
    {
        await using var host = await HostAsync(flag: false);
        var entry = ApprovalRoutes.Gated.First(e => e.Operation == ApprovalOperations.IssuerRetire);

        var response = await host.Sub("sub-alice").SendAsync(Send(entry, Guid.NewGuid().ToString()), Ct);

        Assert.False(await IsApprovalRefusalAsync(response));
    }

    // ── the gates ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task TheOwnerOfACertificate_DownloadsTheirOwnKeyWithoutAGrant()
    {
        await using var host = await HostAsync();
        var id = await SeedRequestAsync(host, "sub-alice");
        var entry = ApprovalRoutes.Gated.First(e => e.Operation == ApprovalOperations.KeyExport);

        var owner = await host.Sub("sub-alice", "someRole").SendAsync(Send(entry, id.ToString()), Ct);
        var adminOwner = await host.Sub("sub-alice").SendAsync(Send(entry, id.ToString()), Ct);

        Assert.False(await IsApprovalRefusalAsync(owner));
        Assert.False(await IsApprovalRefusalAsync(adminOwner));
        Assert.Equal(HttpStatusCode.OK, adminOwner.StatusCode);
    }

    [Fact]
    public async Task ANonAdminWhoIsNotTheOwner_GetsTheOrdinary403_NotTheApprovalRefusal()
    {
        await using var host = await HostAsync();
        var id = await SeedRequestAsync(host, "sub-owner");
        var entry = ApprovalRoutes.Gated.First(e => e.Operation == ApprovalOperations.KeyExport);

        var response = await host.Sub("sub-nobody", "someRole").SendAsync(Send(entry, id.ToString()), Ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.False(await IsApprovalRefusalAsync(response));
    }

    [Fact]
    public async Task AMissingCertificate_IsLeftToTheHandler()
    {
        await using var host = await HostAsync();
        var entry = ApprovalRoutes.Gated.First(e => e.Operation == ApprovalOperations.KeyExport);

        var response = await host.Sub("sub-alice").SendAsync(Send(entry, Guid.NewGuid().ToString()), Ct);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task BulkRenew_IsNeverGated_AndBulkRevoke_Is()
    {
        await using var host = await HostAsync();
        var entry = ApprovalRoutes.Gated.First(e => e.Operation == ApprovalOperations.BulkRevoke);
        var renew = await SeedBulkAsync(host, BulkOperationKind.Renew);
        var revoke = await SeedBulkAsync(host, BulkOperationKind.Revoke);
        var alice = host.Sub("sub-alice");

        Assert.False(await IsApprovalRefusalAsync(await alice.SendAsync(Send(entry, renew.ToString()), Ct)));
        Assert.True(await IsApprovalRefusalAsync(await alice.SendAsync(Send(entry, revoke.ToString()), Ct)));
    }

    [Fact]
    public async Task ACallerWithoutThePermissionForBulkRevoke_Gets403FromTheHandler_NotTheApprovalRefusal()
    {
        await using var host = await HostAsync();
        var entry = ApprovalRoutes.Gated.First(e => e.Operation == ApprovalOperations.BulkRevoke);
        var revoke = await SeedBulkAsync(host, BulkOperationKind.Revoke);

        var response = await host.Sub("sub-nobody", "nobody").SendAsync(Send(entry, revoke.ToString()), Ct);

        Assert.False(await IsApprovalRefusalAsync(response));
    }

    [Fact]
    public async Task AHandlerAnswering4xx_ReleasesTheGrant_SoItCanBeUsedAgain()
    {
        await using var host = await HostAsync();
        var entry = ApprovalRoutes.Gated.First(e => e.Operation == ApprovalOperations.BulkRevoke);
        var revoke = (await SeedBulkAsync(host, BulkOperationKind.Revoke)).ToString();
        var grant = await SeedGrantAsync(host, "sub-alice", entry.Operation, revoke);
        var alice = host.Sub("sub-alice");

        // A wrong confirmCount is refused by the handler after the claim.
        var bad = new HttpRequestMessage(HttpMethod.Post, $"/v1/bulk-operations/{revoke}/execute")
        {
            Content = new StringContent("""{"confirmCount":999}""", Encoding.UTF8, "application/json")
        };
        var response = await alice.SendAsync(bad, Ct);

        Assert.True((int)response.StatusCode >= 400);
        Assert.False(await IsApprovalRefusalAsync(response));
        Assert.Equal(ApprovalStatus.Approved, await StatusOfAsync(host, grant));
    }

    [Fact]
    public async Task AStepUpChallenge_ComesBeforeTheApprovalRefusal_AndLeavesTheGrantAlone()
    {
        var now = new DateTimeOffset(2026, 10, 18, 12, 0, 0, TimeSpan.Zero);
        await using var host = await HostAsync(configure: services =>
        {
            services.RemoveAll<StepUpEvaluator>();
            services.AddSingleton(new StepUpEvaluator(new StepUpOptions { Enabled = true, AcrValues = "mfa", MaxAgeSeconds = 300 }, new FakeTimeProvider(now)));
        });
        var entry = ApprovalRoutes.Gated.First(e => e.Operation == ApprovalOperations.IssuerRetire);
        var target = Guid.NewGuid().ToString();
        var grant = await SeedGrantAsync(host, "sub-alice", entry.Operation, target);
        var client = host.Factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = AuthenticationHeaderValue.Parse("Test-Sub sub-alice");

        var response = await client.SendAsync(Send(entry, target), Ct);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("insufficient_user_authentication", string.Join(' ', response.Headers.GetValues("WWW-Authenticate")));
        Assert.Equal(ApprovalStatus.Approved, await StatusOfAsync(host, grant));
    }
}
