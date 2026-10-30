using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;

namespace Qertum.Tests.Issuers;

/// <summary>
/// "Show only valid certificates": with <c>validOnly=true</c> the certificate list, its chip counts and the issuer
/// list leave out what can no longer be used (expired, revoked or being revoked, or under a CA that is revoked or
/// expired) and keep what can, including a renewed original that has not expired yet. Without the parameter the
/// lists are unchanged, which is what <c>qca</c> and the other callers get.
/// </summary>
public sealed class ValidOnlyListTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static async Task<Issuer> CaAsync(IssuerApiHost host, string name, Action<Issuer>? change = null)
    {
        var added = await host.Kit.AddOnlineRootAsync(name);
        if (change is null) return added;
        await using var db = host.Kit.Database.CreateContext();
        var issuer = await db.Issuers.SingleAsync(i => i.Id == added.Id, Ct);
        change(issuer);
        await db.SaveChangesAsync(Ct);
        return issuer;
    }

    private static async Task<CertificateRequest> CertificateAsync(IssuerApiHost host, string name, IssuerId? issuer,
        CertificateRequestStatus status = CertificateRequestStatus.Issued, int validDays = 300, CertificateRequestId? renewedFrom = null)
    {
        var row = new CertificateRequest
        {
            CommonName = name, RequestedBy = "seed", Type = "WebServer", Status = status, IssuerId = issuer,
            ValidFrom = DateTime.UtcNow.AddDays(-1), ValidTo = DateTime.UtcNow.AddDays(validDays), RenewedFromId = renewedFrom
        };
        await using var db = host.Kit.Database.CreateContext();
        db.CertificateRequests.Add(row);
        await db.SaveChangesAsync(Ct);
        return row;
    }

    private static async Task<string[]> IssuedNamesAsync(IssuerApiHost host, string query)
    {
        var page = await host.Admin().GetFromJsonAsync<PagedResult<CertificateRequest>>(
            $"/v1/certificate-requests/issued?pageSize=500{query}", Ct);
        return page!.Items.Select(r => r.CommonName).Order(StringComparer.Ordinal).ToArray();
    }

    [Fact]
    public async Task IssuedList_ValidOnly_LeavesOutExpiredRevokedAndCompromised_AndKeepsARenewedPair()
    {
        await using var host = new IssuerApiHost();
        var good = await CaAsync(host, "Good Root");
        var revokedRoot = await CaAsync(host, "Revoked Root", i => { i.RevokedAtUtc = DateTime.UtcNow; i.Status = IssuerStatus.Retired; });
        var underRevoked = await CaAsync(host, "Under Revoked", i => { i.Kind = IssuerKind.Intermediate; i.ParentIssuerId = revokedRoot.Id; });
        var expiredCa = await CaAsync(host, "Expired CA", i => { i.Kind = IssuerKind.Intermediate; i.ParentIssuerId = good.Id; i.ValidTo = DateTime.UtcNow.AddDays(-1); });

        await CertificateAsync(host, "good", good.Id);
        await CertificateAsync(host, "expiring", good.Id, validDays: 10);
        var original = await CertificateAsync(host, "original", good.Id, validDays: 20);
        await CertificateAsync(host, "renewal", good.Id, renewedFrom: original.Id);
        await CertificateAsync(host, "expired", good.Id, validDays: -1);
        await CertificateAsync(host, "revoked", good.Id, CertificateRequestStatus.Revoked);
        await CertificateAsync(host, "revoking", good.Id, CertificateRequestStatus.PendingRevocation);
        await CertificateAsync(host, "under-revoked-root", revokedRoot.Id);
        await CertificateAsync(host, "under-child-of-revoked", underRevoked.Id);
        await CertificateAsync(host, "under-expired-ca", expiredCa.Id);

        Assert.Equal(["expiring", "good", "original", "renewal"], await IssuedNamesAsync(host, "&validOnly=true"));
        Assert.Equal(10, (await IssuedNamesAsync(host, "")).Length); // unchanged without the parameter

        var counts = await host.Admin().GetFromJsonAsync<IssuedCertificateCounts>(
            "/v1/certificate-requests/issued/validity-counts?validOnly=true", Ct);
        Assert.Equal(4, counts!.Total);
        Assert.Equal(2, counts.CountFor(IssuedCertificateFilter.Valid));
        Assert.Equal(2, counts.CountFor(IssuedCertificateFilter.Expiring));
        Assert.Equal(0, counts.CountFor(IssuedCertificateFilter.Expired) + counts.CountFor(IssuedCertificateFilter.Revoked)
                        + counts.CountFor(IssuedCertificateFilter.Revoking));

        var all = await host.Admin().GetFromJsonAsync<IssuedCertificateCounts>("/v1/certificate-requests/issued/validity-counts", Ct);
        Assert.Equal(10, all!.Total);
    }

    [Fact]
    public async Task IssuedList_ValidOnly_LeavesOutCertificatesOfARevokedLegacyRoot()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy("Legacy Root");
        var legacy = await host.DefaultIssuerIdAsync(Ct);
        await CertificateAsync(host, "legacy-leaf", issuer: null);
        Assert.Equal(["legacy-leaf"], await IssuedNamesAsync(host, "&validOnly=true"));

        await using (var db = host.Kit.Database.CreateContext())
        {
            var row = await db.Issuers.SingleAsync(i => i.Id == legacy, Ct);
            row.RevokedAtUtc = DateTime.UtcNow;
            await db.SaveChangesAsync(Ct);
        }

        Assert.Empty(await IssuedNamesAsync(host, "&validOnly=true"));
    }

    [Fact]
    public async Task IssuerList_ValidOnly_KeepsLiveRetiredAndPendingCas_AndLeavesOutBrokenOnes()
    {
        await using var host = new IssuerApiHost();
        var good = await CaAsync(host, "Good Root");
        await CaAsync(host, "Renewed Away", i => i.Status = IssuerStatus.Retired);
        await CaAsync(host, "Awaiting Certificate", i => { i.Kind = IssuerKind.Intermediate; i.ParentIssuerId = good.Id; i.Status = IssuerStatus.PendingCertificate; });
        var revoked = await CaAsync(host, "Revoked Root", i => { i.RevokedAtUtc = DateTime.UtcNow; i.Status = IssuerStatus.Retired; });
        await CaAsync(host, "Under Revoked", i => { i.Kind = IssuerKind.Intermediate; i.ParentIssuerId = revoked.Id; });
        await CaAsync(host, "Expired CA", i => i.ValidTo = DateTime.UtcNow.AddDays(-1));
        await CaAsync(host, "Archived CA", i => i.Status = IssuerStatus.Archived);
        await CaAsync(host, "Destroyed CA", i => i.Status = IssuerStatus.Destroyed);
        await host.Registry.InvalidateAsync(Ct);

        var valid = await host.Admin().GetFromJsonAsync<List<IssuerResponse>>("/v1/issuers?validOnly=true", Ct);
        Assert.Equal(["Awaiting Certificate", "Good Root", "Renewed Away"], valid!.Select(i => i.Name).Order(StringComparer.Ordinal));

        var all = await host.Admin().GetFromJsonAsync<List<IssuerResponse>>("/v1/issuers", Ct);
        Assert.Equal(8, all!.Count);
    }
}
