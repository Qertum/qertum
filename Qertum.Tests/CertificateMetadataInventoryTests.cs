using Qertum.Services;

namespace Qertum.Tests;

public sealed class CertificateMetadataInventoryTests
{
    [Fact]
    public async Task Inventory_CarriesTheMetadataOnEveryLeg_AndAnEmptySetWhenNothingWasRecorded()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var host = await MetadataTestHost.CreateAsync();
        using var primary = TestCertificates.CreateSelfSigned("CN=meta-inventory.local");
        using var pqc = TestCertificates.CreateSelfSigned("CN=meta-inventory-pqc.local");
        using var plain = TestCertificates.CreateSelfSigned("CN=plain-inventory.local");
        host.Db.CertificateRequests.AddRange(
            new CertificateRequest
            {
                CommonName = "meta-inventory.local", RequestedBy = "alice", Status = CertificateRequestStatus.Issued,
                CertificatePem = primary.ExportCertificatePem(), PqcCertificatePem = pqc.ExportCertificatePem(),
                Metadata = new CertificateMetadata { OwnerTeam = "Platform", CompatibilityNote = "Java 8" }
            },
            new CertificateRequest
            {
                CommonName = "plain-inventory.local", RequestedBy = "alice", Status = CertificateRequestStatus.Issued,
                CertificatePem = plain.ExportCertificatePem()
            });
        await host.Db.SaveChangesAsync(ct);

        var page = await new CertificateInventoryService(host.Db).GetAsync(1, 10, ct);

        var tagged = page.Items.Where(i => i.Metadata.OwnerTeam == "Platform").ToList();
        Assert.Equal(["pqc", "primary"], tagged.Select(i => i.Leg).Order(StringComparer.Ordinal));
        Assert.All(tagged, i => Assert.Equal("Java 8", i.Metadata.CompatibilityNote));
        Assert.Equal(new CertificateMetadata(), page.Items.Single(i => i.Metadata.OwnerTeam is null).Metadata);
    }
}
