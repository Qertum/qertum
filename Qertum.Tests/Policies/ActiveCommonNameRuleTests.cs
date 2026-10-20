using Qertum.Services;

namespace Qertum.Tests.Policies;

public sealed class ActiveCommonNameRuleTests
{
    [Fact]
    public void Applies_ToAnOrdinaryLeafRequest()
    {
        Assert.True(ActiveCommonNameRule.Applies(new CertificateRequest { CommonName = "a.example.com", Type = "WebServer" }));
    }

    [Fact]
    public void DoesNotApply_ToARootCaRequest()
    {
        Assert.False(ActiveCommonNameRule.Applies(
            new CertificateRequest { CommonName = "Root", Type = WellKnownCertificateTypes.RootCa }));
    }

    [Fact]
    public void DoesNotApply_ToARenewal()
    {
        Assert.False(ActiveCommonNameRule.Applies(new CertificateRequest
        {
            CommonName = "a.example.com",
            Type = "WebServer",
            RenewedFromId = Guid.NewGuid()
        }));
    }

    [Fact]
    public async Task IsTaken_IgnoresRejectedAndRevokedRows()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        scope.Db.CertificateRequests.Add(new CertificateRequest
        {
            CommonName = "dead.example.com",
            RequestedBy = "test",
            Type = "WebServer",
            Status = CertificateRequestStatus.Revoked
        });
        scope.Db.CertificateRequests.Add(new CertificateRequest
        {
            CommonName = "live.example.com",
            RequestedBy = "test",
            Type = "WebServer",
            Status = CertificateRequestStatus.Issued
        });
        await scope.Db.SaveChangesAsync(ct);

        Assert.False(await ActiveCommonNameRule.IsTakenAsync(scope.Db, "dead.example.com", ct));
        Assert.True(await ActiveCommonNameRule.IsTakenAsync(scope.Db, "live.example.com", ct));
    }
}
