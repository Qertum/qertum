using Microsoft.EntityFrameworkCore;
using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Org.BouncyCastle.Security;
using Qertum.Services;
using Qertum.Services.Crypto;
using Qertum.Services.Issuers;

namespace Qertum.Tests.Issuers;

public sealed class ForceReplaceTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static (string Cert, string Key) NewCaPem(CertificateKeyAlgorithm algorithm = CertificateKeyAlgorithm.EcdsaP256)
    {
        var key = AlgorithmStrategyFactory.CreateIssuer(algorithm).GenerateCaKeyPair(new SecureRandom());
        var cert = CaCertificateBuilder.BuildRoot(new LocalKeyPairCaSigner(key),
            CaCertificateBuilder.SubjectName("Replacement Root", null, null, null, null, null),
            DateTime.UtcNow.AddMinutes(-5), DateTime.UtcNow.AddYears(10));
        return (QertumKeyCodec.WriteCertificatePem(cert), QertumKeyCodec.WritePrivateKeyPem(key.Private));
    }

    [Fact]
    public async Task ForceImport_ReplacesTheDefault_DestroysTheOldKey_AndOldSerialsBecomeUnknown()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy("Old Root");
        var oldId = await host.DefaultIssuerIdAsync(Ct);
        var oldSerial = await host.SeedIssuedAsync(oldId, host.Kit.Legacy, revoked: false, Ct);
        var oldCert = QertumKeyCodec.ReadCertificatePem(host.Kit.Legacy.GetCaCertificatePem())!;
        var (cert, key) = NewCaPem();

        var response = await host.Admin().PostAsJsonAsync("/v1/ca/import?force=true",
            new ImportCaRequest { CertificatePem = cert, PrivateKeyPem = key, Confirm = "REPLACE Old Root" }, Ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False(File.Exists(Path.Combine(host.Kit.CaDataDirectory, "ca.key")));
        var old = await host.Admin().GetFromJsonAsync<IssuerResponse>($"/v1/issuers/{oldId}", Ct);
        Assert.Equal(IssuerStatus.Destroyed, old!.Status);
        var next = await host.Registry.GetDefaultAsync(Ct);
        Assert.Contains("CN=Replacement Root", next!.Issuer.SubjectDn);
        Assert.True(next.CanIssue);
        Assert.Equal(HttpStatusCode.NotFound, (await host.Anonymous().GetAsync($"/crl/{oldId}", Ct)).StatusCode);
        // OCSP for the destroyed issuer's serial: no issuer matches the CertID any more, so unknown.
        var ocspRequest = new Org.BouncyCastle.Ocsp.OcspReqGenerator();
        ocspRequest.AddRequest(new Org.BouncyCastle.Ocsp.CertificateID(
            new Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier(Org.BouncyCastle.Asn1.Oiw.OiwObjectIdentifiers.IdSha1, Org.BouncyCastle.Asn1.DerNull.Instance), oldCert,
            new Org.BouncyCastle.Math.BigInteger(oldSerial, 16)));
        var ocsp = await host.Anonymous().PostAsync("/ocsp", new ByteArrayContent(ocspRequest.Generate().GetEncoded()), Ct);
        var basic = (Org.BouncyCastle.Ocsp.BasicOcspResp)new Org.BouncyCastle.Ocsp.OcspResp(
            await ocsp.Content.ReadAsByteArrayAsync(Ct)).GetResponseObject();
        Assert.IsType<Org.BouncyCastle.Ocsp.UnknownStatus>(basic.Responses.Single().GetCertStatus());
    }

    [Fact]
    public async Task WithoutForce_Is409()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy("Old Root");
        var (cert, key) = NewCaPem();

        var response = await host.Admin().PostAsJsonAsync("/v1/ca/import", new ImportCaRequest { CertificatePem = cert, PrivateKeyPem = key }, Ct);

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("REPLACE old root")]
    [InlineData("REPLACE Old Root ")]
    public async Task WrongConfirmation_Is400_AndChangesNothing(string? confirm)
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy("Old Root");
        var (cert, key) = NewCaPem();

        var response = await host.Admin().PostAsJsonAsync("/v1/ca/import?force=true",
            new ImportCaRequest { CertificatePem = cert, PrivateKeyPem = key, Confirm = confirm }, Ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.True(File.Exists(Path.Combine(host.Kit.CaDataDirectory, "ca.key")));
    }

    [Fact]
    public async Task Force_NeedsAdminRole_EvenWithSettingsEdit()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy("Old Root");
        await host.GrantAsync("ops", AppPermissions.SettingsEdit);
        var (cert, key) = NewCaPem();

        var response = await host.Role("ops").PostAsJsonAsync("/v1/ca/import?force=true",
            new ImportCaRequest { CertificatePem = cert, PrivateKeyPem = key, Confirm = "REPLACE Old Root" }, Ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.True(File.Exists(Path.Combine(host.Kit.CaDataDirectory, "ca.key")));
    }

    [Fact]
    public async Task ForceImport_WithAMismatchedKey_Is400_AndLeavesOldCaIntact()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy("Old Root");
        var oldId = await host.DefaultIssuerIdAsync(Ct);
        var (cert, _) = NewCaPem();
        var (_, otherKey) = NewCaPem();

        var response = await host.Admin().PostAsJsonAsync("/v1/ca/import?force=true",
            new ImportCaRequest { CertificatePem = cert, PrivateKeyPem = otherKey, Confirm = "REPLACE Old Root" }, Ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(oldId, await host.DefaultIssuerIdAsync(Ct));
        Assert.True(File.Exists(Path.Combine(host.Kit.CaDataDirectory, "ca.key")));
        Assert.False(Directory.Exists(Path.Combine(host.Kit.CaDataDirectory, "issuers"))
                     && Directory.EnumerateFiles(Path.Combine(host.Kit.CaDataDirectory, "issuers"), "*", SearchOption.AllDirectories).Any());
    }

    [Fact]
    public async Task ForceImport_RefusedByPqcOnly_LeavesOldCaIntact()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy("Old Root", CertificateKeyAlgorithm.MlDsa65);
        await using (var db = host.Kit.Database.CreateContext())
        {
            (await db.Settings.SingleAsync(Ct)).PqcStage = PqcStage.Enforce;
            await db.SaveChangesAsync(Ct);
        }
        var (cert, key) = NewCaPem(CertificateKeyAlgorithm.EcdsaP256);

        var response = await host.Admin().PostAsJsonAsync("/v1/ca/import?force=true",
            new ImportCaRequest { CertificatePem = cert, PrivateKeyPem = key, Confirm = "REPLACE Old Root" }, Ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var handle = await host.Registry.GetDefaultAsync(Ct);
        Assert.True(handle!.Issuer.LegacyFiles);
        Assert.True(handle.CanIssue);
        Assert.NotEmpty(handle.Generator!.GenerateCertificate(new CertificateRequest { CommonName = "still.example" }, new CaSettings { PqcStage = PqcStage.Off }).CertificatePem);
    }

    [Fact]
    public async Task ForceGenerate_FilesARootRequest_AndReplacesOnlyWhenItIsSigned()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy("Old Root");
        var oldId = await host.DefaultIssuerIdAsync(Ct);

        var filed = await host.Admin().PostAsJsonAsync("/v1/ca/generate?force=true",
            new GenerateCaRequest { CommonName = "Generated Root", KeyAlgorithm = CertificateKeyAlgorithm.EcdsaP384, Confirm = "REPLACE Old Root" }, Ct);
        Assert.Equal(HttpStatusCode.Created, filed.StatusCode);
        var request = await filed.Content.ReadFromJsonAsync<CertificateRequest>(Ct);
        Assert.Equal(oldId, await host.DefaultIssuerIdAsync(Ct)); // nothing replaced yet

        using var scope = host.Factory.Services.CreateScope();
        var requests = scope.ServiceProvider.GetRequiredService<ICertificateRequestService>();
        var row = (await requests.GetByIdAsync(request!.Id, Ct))!;
        var signed = await scope.ServiceProvider.GetRequiredService<IssuanceSigner>().SignAsync(row, new CaSettings { PqcStage = PqcStage.Off }, Ct);

        var next = await host.Registry.GetDefaultAsync(Ct);
        Assert.Equal((Guid)request.Id, next!.Issuer.Id.Value);
        Assert.Equal(next.Issuer.Id, signed.IssuerId);
        Assert.True(next.CanIssue);
        Assert.False(File.Exists(Path.Combine(host.Kit.CaDataDirectory, "ca.key")));

        // A retry of the same request (DB write after signing failed) returns the installed root.
        var again = await scope.ServiceProvider.GetRequiredService<IssuanceSigner>().SignAsync(row, new CaSettings { PqcStage = PqcStage.Off }, Ct);
        Assert.Equal(signed.CertificatePem, again.CertificatePem);
    }

    [Fact]
    public async Task ForceGenerate_AfterTheDefaultChanged_RefusesToReplace()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy("Old Root");
        await host.DefaultIssuerIdAsync(Ct);
        var filed = await (await host.Admin().PostAsJsonAsync("/v1/ca/generate?force=true",
            new GenerateCaRequest { CommonName = "Stale", Confirm = "REPLACE Old Root" }, Ct)).Content.ReadFromJsonAsync<CertificateRequest>(Ct);
        var other = await host.Kit.AddOnlineRootAsync("Other Root");
        await host.Registry.InvalidateAsync(Ct);
        (await host.Admin().PostAsync($"/v1/issuers/{other.Id}/make-default", null, Ct)).EnsureSuccessStatusCode();

        using var scope = host.Factory.Services.CreateScope();
        var row = (await scope.ServiceProvider.GetRequiredService<ICertificateRequestService>().GetByIdAsync(filed!.Id, Ct))!;

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            scope.ServiceProvider.GetRequiredService<IssuanceSigner>().SignAsync(row, new CaSettings { PqcStage = PqcStage.Off }, Ct));
        Assert.Equal(other.Id, await host.DefaultIssuerIdAsync(Ct));
        Assert.True(File.Exists(Path.Combine(host.Kit.CaDataDirectory, "ca.key")));
    }

    [Fact]
    public async Task ForceGenerate_RejectedRequest_LeavesOldCaIntact()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy("Old Root");
        var oldId = await host.DefaultIssuerIdAsync(Ct);
        var filed = await (await host.Admin().PostAsJsonAsync("/v1/ca/generate?force=true",
            new GenerateCaRequest { CommonName = "Never", Confirm = "REPLACE Old Root" }, Ct)).Content.ReadFromJsonAsync<CertificateRequest>(Ct);

        (await host.Admin().PostAsync($"/v1/certificate-requests/{filed!.Id}/reject", null, Ct)).EnsureSuccessStatusCode();

        Assert.Equal(oldId, await host.DefaultIssuerIdAsync(Ct));
        Assert.True(File.Exists(Path.Combine(host.Kit.CaDataDirectory, "ca.key")));
    }

    [Fact]
    public async Task ReplaceDefault_AuditsTheUnrevocableCount()
    {
        using var kit = new IssuerTestKit();
        kit.InitializeLegacy("Counted Root");
        var registry = kit.NewRegistry();
        var legacy = (await registry.GetDefaultAsync(Ct))!.Issuer;
        await using (var db = kit.Database.CreateContext())
        {
            foreach (var validTo in new[] { DateTime.UtcNow.AddDays(10), DateTime.UtcNow.AddDays(20), DateTime.UtcNow.AddDays(-1) })
                db.CertificateRequests.Add(new CertificateRequest
                {
                    CommonName = $"{Guid.NewGuid():N}.example", RequestedBy = "seed", Status = CertificateRequestStatus.Issued,
                    CertificatePem = "pem", ValidTo = validTo, IssuerId = legacy.Id
                });
            await db.SaveChangesAsync(Ct);
        }
        var audit = new RecordingAuditLog();
        await using var scope = kit.Scopes.CreateAsyncScope();
        var lifecycle = new IssuerLifecycleService(scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>(),
            registry, kit.Storage, audit, new NullWebhooks());
        var (certPem, _) = NewCaPem();
        var replacement = new Issuer { Name = "Replacement", Kind = IssuerKind.Root, KeyCustody = IssuerKeyCustody.Online, CreatedAtUtc = DateTime.UtcNow };
        IssuerCertificateFacts.Read(certPem).ApplyTo(replacement);
        replacement.CertificatePem = certPem;

        var affected = await lifecycle.ReplaceDefaultAsync(legacy, replacement, "test", Ct);

        Assert.Equal(2, affected);
        Assert.Contains(audit.Entries, e => e.Action == "IssuerDestroyed" && e.Detail!.Contains("2 unexpired"));
    }

    private sealed class RecordingAuditLog : IAuditLogService
    {
        public List<(string Action, string? Detail)> Entries { get; } = [];

        public Task LogAsync(string action, string performedBy, Guid? resourceId = null, string? resourceName = null,
            string? detail = null, CancellationToken cancellationToken = default)
        {
            Entries.Add((action, detail));
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<AuditLogEntry>> GetAllAsync(int page = 1, int pageSize = 100, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<AuditLogEntry>>([]);
    }
}
