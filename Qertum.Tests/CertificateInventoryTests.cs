using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using System.Security.Cryptography;
using X509 = System.Security.Cryptography.X509Certificates;

namespace Qertum.Tests;

public sealed class CertificateInventoryTests
{
    [Fact]
    public async Task PairedRequest_ProducesTwoPagedAssets()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(ct);
        await using var db = NewDb(connection);
        await db.Database.EnsureCreatedAsync(ct);
        using var cert = TestCertificates.CreateSelfSigned("CN=inventory.local");
        using var pqcCert = TestCertificates.CreateSelfSigned("CN=inventory-paired.local");
        var renewedFromId = (CertificateRequestId)Guid.NewGuid();
        db.CertificateRequests.Add(new CertificateRequest
        {
            CommonName = "inventory.local", RequestedBy = "Alice", RequestedBySubject = "subject-1",
            Status = CertificateRequestStatus.Issued, CertificatePem = cert.ExportCertificatePem(),
            PqcCertificatePem = pqcCert.ExportCertificatePem(), RenewedFromId = renewedFromId
        });
        await db.SaveChangesAsync(ct);

        var service = new CertificateInventoryService(db);
        var first = await service.GetAsync(1, 1, ct);
        var second = await service.GetAsync(2, 1, ct);

        Assert.Equal(2, first.TotalCount);
        Assert.Equal(2, first.TotalPages);
        Assert.Equal("primary", Assert.Single(first.Items).Leg);
        Assert.Equal("pqc", Assert.Single(second.Items).Leg);
        Assert.Equal("RSA", first.Items[0].SubjectKeyAlgorithm);
        Assert.Equal("subject-1", first.Items[0].OwnerSubject);
        Assert.Equal(renewedFromId, first.Items[0].RenewedFromId);
        Assert.NotEqual(first.Items[0].SerialNumber, second.Items[0].SerialNumber);
        Assert.Equal("Unknown", first.Items[0].DeploymentCompatibility);
    }

    [Fact]
    public async Task GetForRequests_ReturnsBothLegsOfOnlyTheAskedRequests_AndIgnoresOthers()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(ct);
        await using var db = NewDb(connection);
        await db.Database.EnsureCreatedAsync(ct);
        using var cert = TestCertificates.CreateSelfSigned("CN=asked.local");
        using var pqcCert = TestCertificates.CreateSelfSigned("CN=asked-paired.local");
        using var other = TestCertificates.CreateSelfSigned("CN=other.local");
        var asked = new CertificateRequest
        {
            CommonName = "asked.local", RequestedBy = "Alice", Status = CertificateRequestStatus.Issued,
            CertificatePem = cert.ExportCertificatePem(), PqcCertificatePem = pqcCert.ExportCertificatePem()
        };
        var notAsked = new CertificateRequest
        {
            CommonName = "other.local", RequestedBy = "Alice", Status = CertificateRequestStatus.Issued,
            CertificatePem = other.ExportCertificatePem()
        };
        var pending = new CertificateRequest { CommonName = "pending.local", RequestedBy = "Alice", Status = CertificateRequestStatus.Pending };
        db.CertificateRequests.AddRange(asked, notAsked, pending);
        await db.SaveChangesAsync(ct);

        var items = await new CertificateInventoryService(db).GetForRequestsAsync([asked.Id, pending.Id], ct);

        Assert.Equal(["primary", "pqc"], items.Select(i => i.Leg));
        Assert.All(items, i => Assert.Equal(asked.Id, i.RequestId));
        Assert.Empty(await new CertificateInventoryService(db).GetForRequestsAsync([], ct));
    }

    [Fact]
    public async Task GetForRequests_KeepsAMalformedCertificateVisibleWithUnknownFacts()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(ct);
        await using var db = NewDb(connection);
        await db.Database.EnsureCreatedAsync(ct);
        var row = new CertificateRequest
        {
            CommonName = "legacy.local", RequestedBy = "Old", Status = CertificateRequestStatus.Issued,
            CertificatePem = "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----"
        };
        db.CertificateRequests.Add(row);
        await db.SaveChangesAsync(ct);

        var item = Assert.Single(await new CertificateInventoryService(db).GetForRequestsAsync([row.Id], ct));

        Assert.Equal("InvalidCertificate", item.AnalysisStatus);
        Assert.Equal("Unknown", item.SubjectKeyAlgorithm);
        Assert.Equal("Unknown", item.ChainStatus);
    }

    [Fact]
    public async Task MalformedIssuedCertificate_RemainsVisibleWithUnknownFacts()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(ct);
        await using var db = NewDb(connection);
        await db.Database.EnsureCreatedAsync(ct);
        db.CertificateRequests.Add(new CertificateRequest
        {
            CommonName = "legacy.local", RequestedBy = "Old Name", Status = CertificateRequestStatus.Revoked,
            CertificatePem = "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----"
        });
        db.CertificateRequests.Add(new CertificateRequest
        {
            CommonName = "pending.local", RequestedBy = "Alice", Status = CertificateRequestStatus.Pending
        });
        await db.SaveChangesAsync(ct);

        var item = Assert.Single((await new CertificateInventoryService(db).GetAsync(1, 50, ct)).Items);

        Assert.Null(item.OwnerSubject);
        Assert.Equal("Unknown", item.SubjectKeyAlgorithm);
        Assert.Equal("InvalidCertificate", item.AnalysisStatus);
        Assert.False(string.IsNullOrWhiteSpace(System.Text.Json.JsonSerializer.SerializeToElement(item,
            new System.Text.Json.JsonSerializerOptions(System.Text.Json.JsonSerializerDefaults.Web))
            .GetProperty("analysisError").GetString()));
    }

    [Fact]
    public async Task EmptyIssuedCertificate_RemainsVisibleWithAnalysisError()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(ct);
        await using var db = NewDb(connection);
        await db.Database.EnsureCreatedAsync(ct);
        db.CertificateRequests.Add(new CertificateRequest
        {
            CommonName = "empty.local", RequestedBy = "Alice", Status = CertificateRequestStatus.Issued,
            CertificatePem = string.Empty, PqcCertificatePem = string.Empty
        });
        await db.SaveChangesAsync(ct);

        var result = await new CertificateInventoryService(db).GetAsync(1, 50, ct);

        Assert.Equal(2, result.TotalCount);
        Assert.Equal(["primary", "pqc"], result.Items.Select(item => item.Leg));
        Assert.All(result.Items, item =>
        {
            Assert.Equal("InvalidCertificate", item.AnalysisStatus);
            Assert.False(string.IsNullOrWhiteSpace(item.AnalysisError));
        });
    }

    [Fact]
    public async Task SignedLeaf_VerifiesOnlyAgainstItsCurrentRoot()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(ct);
        await using var db = NewDb(connection);
        await db.Database.EnsureCreatedAsync(ct);

        using var rootKey = RSA.Create(2048);
        var rootRequest = new X509.CertificateRequest("CN=Inventory Root", rootKey,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootRequest.CertificateExtensions.Add(new X509.X509BasicConstraintsExtension(true, false, 0, true));
        using var root = rootRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        using var leafKey = RSA.Create(2048);
        var leafRequest = new X509.CertificateRequest("CN=inventory-leaf.local", leafKey,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var leaf = leafRequest.Create(root, DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddMonths(6), [1, 2, 3, 4]);
        db.CertificateRequests.Add(new CertificateRequest
        {
            CommonName = "inventory-leaf.local", RequestedBy = "Alice", Status = CertificateRequestStatus.Issued,
            CertificatePem = leaf.ExportCertificatePem()
        });
        await db.SaveChangesAsync(ct);

        var verified = Assert.Single((await new CertificateInventoryService(db,
            new InventoryGenerator(root.ExportCertificatePem())).GetAsync(1, 50, ct)).Items);
        using var other = TestCertificates.CreateSelfSigned("CN=Another Root");
        var unmatched = Assert.Single((await new CertificateInventoryService(db,
            new InventoryGenerator(other.ExportCertificatePem())).GetAsync(1, 50, ct)).Items);

        Assert.Equal("SignatureVerifiedWithCurrentRoot", verified.ChainStatus);
        Assert.Equal("RSA", verified.CurrentRootKeyAlgorithm);
        Assert.Contains("Inventory Root", verified.CurrentRootSubjectDn);
        Assert.Equal(64, verified.CurrentRootSha256Fingerprint?.Length);
        Assert.Equal("Unknown", unmatched.ChainStatus);
        Assert.Null(unmatched.CurrentRootKeyAlgorithm);
    }

    [Fact]
    public async Task UnsupportedSubjectKey_IsUnknownRatherThanRsa()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(ct);
        await using var db = NewDb(connection);
        await db.Database.EnsureCreatedAsync(ct);
        db.CertificateRequests.Add(new CertificateRequest
        {
            CommonName = "legacy-ed25519.local", RequestedBy = "Alice", Status = CertificateRequestStatus.Issued,
            CertificatePem = TestCertificates.CreateSelfSignedEd25519Pem("CN=legacy-ed25519.local")
        });
        await db.SaveChangesAsync(ct);

        var item = Assert.Single((await new CertificateInventoryService(db).GetAsync(1, 50, ct)).Items);

        Assert.Equal("Parsed", item.AnalysisStatus);
        Assert.Equal("Unknown", item.SubjectKeyAlgorithm);
        Assert.False(string.IsNullOrWhiteSpace(System.Text.Json.JsonSerializer.SerializeToElement(item,
            new System.Text.Json.JsonSerializerOptions(System.Text.Json.JsonSerializerDefaults.Web))
            .GetProperty("analysisError").GetString()));
    }

    [Fact]
    public async Task APair_ListsTwoItems_WithTheirOwnMlDsaAndMlKemFacts()
    {
        var ct = TestContext.Current.CancellationToken;
        using var kit = new Qertum.Tests.Issuers.IssuerTestKit();
        kit.InitializeLegacy();
        var generated = kit.Legacy.GenerateCertificate(
            new CertificateRequest { CommonName = "mail-pair.local", KeyAlgorithm = CertificateKeyAlgorithm.PairMlDsa65MlKem768 },
            new CaSettings { PqcStage = PqcStage.Off });

        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(ct);
        await using var db = NewDb(connection);
        await db.Database.EnsureCreatedAsync(ct);
        db.CertificateRequests.Add(new CertificateRequest
        {
            CommonName = "mail-pair.local", RequestedBy = "Alice", RequestedBySubject = "subject-1",
            Status = CertificateRequestStatus.Issued, KeyAlgorithm = CertificateKeyAlgorithm.PairMlDsa65MlKem768,
            CertificatePem = generated.CertificatePem, PqcCertificatePem = generated.PqcCertificatePem
        });
        await db.SaveChangesAsync(ct);

        var page = await new CertificateInventoryService(db).GetAsync(1, 10, ct);

        Assert.Equal(2, page.Items.Count);
        Assert.Equal("ML-DSA-65", page.Items.Single(i => i.Leg == "primary").SubjectKeyAlgorithm);
        Assert.Equal("ML-KEM-768", page.Items.Single(i => i.Leg == "pqc").SubjectKeyAlgorithm);
    }

    private static CertificateRequestDbContext NewDb(SqliteConnection connection) =>
        new(new DbContextOptionsBuilder<CertificateRequestDbContext>().UseSqlite(connection).Options,
            new EphemeralDataProtectionProvider());

    [Fact]
    public async Task Inventory_VerifiesEachRowAgainstItsOwnIssuer()
    {
        var ct = TestContext.Current.CancellationToken;
        using var kit = new Qertum.Tests.Issuers.IssuerTestKit();
        kit.InitializeLegacy();
        var registry = kit.NewRegistry();
        await registry.GetDefaultAsync(ct);
        var second = await kit.AddOnlineRootAsync("Inventory Second");
        await registry.InvalidateAsync(ct);
        var secondGen = kit.NewGenerator(kit.Storage.OptionsFor(second));
        await using (var seed = kit.Database.CreateContext())
        {
            foreach (var (cn, signer) in new[] { ("right.example", (ICertificateGenerator)secondGen), ("wrong.example", kit.Legacy) })
            {
                var issued = signer.GenerateCertificate(new CertificateRequest { CommonName = cn }, new CaSettings { PqcStage = PqcStage.Off });
                seed.CertificateRequests.Add(new CertificateRequest
                {
                    CommonName = cn, RequestedBy = "seed", Status = CertificateRequestStatus.Issued,
                    CertificatePem = issued.CertificatePem, SerialNumber = issued.SerialNumber, ValidTo = issued.ValidTo,
                    IssuerId = second.Id // the "wrong" row claims an issuer that did not sign it
                });
            }
            await seed.SaveChangesAsync(ct);
        }

        await using var db = kit.Database.CreateContext();
        var items = (await new CertificateInventoryService(db, kit.Legacy, registry).GetAsync(1, 50, ct)).Items;

        Assert.Equal("SignatureVerifiedWithCurrentRoot", items.Single(i => i.SubjectDn!.Contains("right.example")).ChainStatus);
        Assert.Equal("Unknown", items.Single(i => i.SubjectDn!.Contains("wrong.example")).ChainStatus);
    }

    [Fact]
    public async Task Inventory_NamesTheSigningIssuer_AndResolvesLegacyRowsToTheLegacyIssuer()
    {
        var ct = TestContext.Current.CancellationToken;
        using var kit = new Qertum.Tests.Issuers.IssuerTestKit();
        kit.InitializeLegacy("Named Legacy");
        var registry = kit.NewRegistry();
        var legacy = (await registry.GetDefaultAsync(ct))!.Issuer;
        var second = await kit.AddOnlineRootAsync("Named Second");
        await registry.InvalidateAsync(ct);
        var secondGen = kit.NewGenerator(kit.Storage.OptionsFor(second));
        await using (var seed = kit.Database.CreateContext())
        {
            foreach (var (cn, signer, issuerId) in new[]
                     {
                         ("second.example", (ICertificateGenerator)secondGen, (IssuerId?)second.Id),
                         ("legacy.example", kit.Legacy, null)
                     })
            {
                var issued = signer.GenerateCertificate(new CertificateRequest { CommonName = cn }, new CaSettings { PqcStage = PqcStage.Off });
                seed.CertificateRequests.Add(new CertificateRequest
                {
                    CommonName = cn, RequestedBy = "seed", Status = CertificateRequestStatus.Issued,
                    CertificatePem = issued.CertificatePem, SerialNumber = issued.SerialNumber, ValidTo = issued.ValidTo,
                    IssuerId = issuerId
                });
            }
            await seed.SaveChangesAsync(ct);
        }

        await using var db = kit.Database.CreateContext();
        var items = (await new CertificateInventoryService(db, kit.Legacy, registry).GetAsync(1, 50, ct)).Items;

        var fromSecond = items.Single(i => i.SubjectDn!.Contains("second.example"));
        Assert.Equal(second.Id, fromSecond.IssuerId);
        Assert.Equal("Named Second", fromSecond.IssuerName);
        var fromLegacy = items.Single(i => i.SubjectDn!.Contains("legacy.example"));
        Assert.Equal(legacy.Id, fromLegacy.IssuerId);
        Assert.Equal("Named Legacy", fromLegacy.IssuerName);
    }
}

file sealed class InventoryGenerator(string pem) : ICertificateGenerator
{
    public bool IsInitialized => true;
    public string GetCaCertificatePem() => pem;
    public CaStatusResponse GetCaStatus() => throw new NotSupportedException();
    public GeneratedCertificate GenerateCa(GenerateCaRequest request) => throw new NotSupportedException();
    public void ImportCa(ImportCaRequest request) => throw new NotSupportedException();
    public GeneratedCertificate GenerateCertificate(CertificateRequest request, CaSettings? caSettings,
        CertificateTemplate? template = null) => throw new NotSupportedException();
    public GeneratedCertificate GenerateFromCsr(string csrDerBase64Url, CertificateRequest request,
        CaSettings? caSettings, CertificateTemplate? template = null) => throw new NotSupportedException();
    public byte[] GenerateCrl(IReadOnlyList<CertificateRequest> revokedRequests, CaSettings? caSettings = null,
        long crlNumber = 0, DateTime? thisUpdateUtc = null) => throw new NotSupportedException();
    public byte[] GenerateDeltaCrl(IReadOnlyList<CertificateRequest> revokedSinceBase, CaSettings? caSettings,
        long crlNumber, long baseCrlNumber, DateTime? thisUpdateUtc = null) => throw new NotSupportedException();
    public byte[] GenerateOcspResponse(byte[] derRequest, IReadOnlyDictionary<string, OcspCertificateStatus> statuses,
        CaSettings? caSettings = null) => throw new NotSupportedException();
    public IReadOnlyList<string> ReadOcspRequestSerials(byte[] derRequest) => throw new NotSupportedException();

}
