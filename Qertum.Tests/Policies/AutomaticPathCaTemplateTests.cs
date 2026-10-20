using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Services.Policies;

namespace Qertum.Tests.Policies;

public sealed class AutomaticPathCaTemplateTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Theory]
    [InlineData("ACME")]
    [InlineData("EST")]
    public async Task SavingACaCapableProtocolTemplate_IsRefused(string protocol)
    {
        await using var scope = await PolicyTestDb.CreateAsync(Ct);
        var settings = new CaSettings { Id = 1, AcmeTemplateTypeKey = "WebServer", EstTemplateTypeKey = "WebServer" };
        if (protocol == "ACME") settings.AcmeTemplateTypeKey = "SubordinateCA"; else settings.EstTemplateTypeKey = "SubordinateCA";

        var error = await scope.CreateManagementService().ValidateSettingsAsync(settings, Ct);

        Assert.NotNull(error);
        Assert.Contains(protocol, error);
        Assert.Contains("SubordinateCA", error);
        Assert.Contains("CA certificate", error);
    }

    [Fact]
    public async Task AutoRenewal_NeverPicksACaCertificate()
    {
        await using var scope = await PolicyTestDb.CreateAsync(Ct);
        var soon = DateTime.UtcNow.AddDays(5);
        foreach (var type in new[] { "WebServer", "SubordinateCA" })
            scope.Db.CertificateRequests.Add(new CertificateRequest
            {
                CommonName = $"{type}.example", RequestedBy = "u", Type = type, Status = CertificateRequestStatus.Issued,
                ValidFrom = DateTime.UtcNow.AddDays(-300), ValidTo = soon
            });
        // A legacy row with no type must not be excluded by the CA-type filter.
        scope.Db.CertificateRequests.Add(new CertificateRequest
        {
            CommonName = "untyped.example", RequestedBy = "u", Type = null, Status = CertificateRequestStatus.Issued,
            ValidFrom = DateTime.UtcNow.AddDays(-300), ValidTo = soon
        });
        await scope.Db.SaveChangesAsync(Ct);

        var due = await scope.CreateRequestService().GetCertsNeedingAutoRenewalAsync(30, Ct);

        Assert.Equal(["WebServer", null], due.Select(r => r.Type).OrderByDescending(t => t).ToArray());
    }
}
