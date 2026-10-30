using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.DependencyInjection;
using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Services.Crypto;
using Qertum.Services.Issuers;

namespace Qertum.Tests.Issuers;

/// <summary>
/// Renewing an intermediate CA: a new key under the same name takes the old one's place. It finishes at once
/// when Qertum holds the parent's key, and through the request file and install otherwise; a live old intermediate
/// is retired, never destroyed.
/// </summary>
public sealed class IntermediateRenewalTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static async Task<Issuer> OnlineRootAsync(IssuerApiHost host, CertificateKeyAlgorithm algorithm = CertificateKeyAlgorithm.EcdsaP256)
    {
        var root = await host.Kit.AddOnlineRootAsync("Root", isDefault: true, algorithm: algorithm);
        await host.Registry.InvalidateAsync(Ct);
        return root;
    }

    private static async Task<IssuerResponse> OnlineIntermediateAsync(IssuerApiHost host, IssuerId parent, string name = "Issuing CA",
        CertificateKeyAlgorithm algorithm = CertificateKeyAlgorithm.EcdsaP256, bool makeDefault = true, int pathLength = 0)
    {
        var response = await host.Admin().PostAsJsonAsync("/v1/issuers/intermediates", new CreateIntermediateRequest
        {
            Name = name, CommonName = name, KeyAlgorithm = algorithm, ValidityDays = 365, PathLength = pathLength,
            PermittedDnsSuffixes = ["corp.example"], ParentIssuerId = parent
        }, Ct);
        Assert.True(response.IsSuccessStatusCode, await response.Content.ReadAsStringAsync(Ct));
        var created = (await response.Content.ReadFromJsonAsync<CreateIntermediateResponse>(Ct))!;
        if (makeDefault)
            (await host.Admin().PostAsync($"/v1/issuers/{created.Issuer.Id}/make-default", null, Ct)).EnsureSuccessStatusCode();
        return created.Issuer;
    }

    internal static Task<HttpResponseMessage> RenewAsync(IssuerApiHost host, IssuerId id, int? validityDays = null) =>
        host.Admin().PostAsJsonAsync($"/v1/issuers/{id}/renew", new RenewIssuerRequest(validityDays), Ct);

    internal static async Task<Issuer> RowAsync(IssuerApiHost host, IssuerId id)
    {
        await using var db = host.Kit.Database.CreateContext();
        return await db.Issuers.AsNoTracking().SingleAsync(i => i.Id == id, Ct);
    }

    internal static async Task ChangeAsync(IssuerApiHost host, IssuerId id, Action<Issuer> change)
    {
        await using (var db = host.Kit.Database.CreateContext())
        {
            change(await db.Issuers.SingleAsync(i => i.Id == id, Ct));
            await db.SaveChangesAsync(Ct);
        }
        await host.Registry.InvalidateAsync(Ct);
    }

    internal static Task RevokeAsync(IssuerApiHost host, IssuerId id) => ChangeAsync(host, id, i =>
    {
        i.RevokedAtUtc = DateTime.UtcNow;
        i.Status = IssuerStatus.Retired;
        i.RetiredAtUtc = DateTime.UtcNow;
        i.IsDefault = false;
    });

    private static async Task SettingsAsync(IssuerApiHost host, Action<CaSettings> change)
    {
        (await host.Admin().GetAsync("/v1/settings", Ct)).EnsureSuccessStatusCode(); // makes sure the row exists
        await using var db = host.Kit.Database.CreateContext();
        change(await db.Settings.SingleAsync(Ct));
        await db.SaveChangesAsync(Ct);
    }

    private static async Task<int> IssuerCountAsync(IssuerApiHost host)
    {
        await using var db = host.Kit.Database.CreateContext();
        return await db.Issuers.CountAsync(Ct);
    }

    [Fact]
    public async Task ALiveIntermediate_RenewsAtOnce_TakesItsPlace_AndTheOldIsRetired()
    {
        await using var host = new IssuerApiHost();
        var root = await OnlineRootAsync(host);
        var old = await OnlineIntermediateAsync(host, root.Id);
        await using (var db = host.Kit.Database.CreateContext())
        {
            (await db.CertificateTemplates.SingleAsync(t => t.TypeKey == "WebServer", Ct)).IssuerId = old.Id;
            await db.SaveChangesAsync(Ct);
        }

        var response = await RenewAsync(host, old.Id);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var renewed = (await response.Content.ReadFromJsonAsync<CreateIntermediateResponse>(Ct))!;
        Assert.Null(renewed.RequestFile);
        Assert.Equal(IssuerStatus.Active, renewed.Issuer.Status);
        Assert.True(renewed.Issuer.IsDefault);
        Assert.Equal(old.Name, renewed.Issuer.Name);
        Assert.Equal(old.SubjectDn, renewed.Issuer.SubjectDn);
        Assert.Equal(old.Id, renewed.Issuer.RenewalOfIssuerId);
        Assert.Equal(root.Id, renewed.Issuer.ParentIssuerId);
        Assert.Equal(old.PermittedDnsSuffixes, renewed.Issuer.PermittedDnsSuffixes);
        Assert.NotEqual((await RowAsync(host, old.Id)).SpkiSha256, (await RowAsync(host, renewed.Issuer.Id)).SpkiSha256);

        var retired = await RowAsync(host, old.Id);
        Assert.Equal(IssuerStatus.Retired, retired.Status);
        Assert.False(retired.IsDefault);
        Assert.Null(retired.DestroyedAtUtc);
        Assert.Equal(HttpStatusCode.OK, (await host.Anonymous().GetAsync($"/crl/{old.Id}", Ct)).StatusCode);
        await using (var db = host.Kit.Database.CreateContext())
            Assert.Equal(renewed.Issuer.Id, (await db.CertificateTemplates.SingleAsync(t => t.TypeKey == "WebServer", Ct)).IssuerId);
    }

    [Fact]
    public async Task ARevokedDefaultIntermediate_Renewed_RefillsTheDefaultSeat()
    {
        await using var host = new IssuerApiHost();
        var root = await OnlineRootAsync(host);
        var old = await OnlineIntermediateAsync(host, root.Id);
        await RevokeAsync(host, old.Id);
        await ChangeAsync(host, root.Id, i => i.IsDefault = false);
        Assert.False((await host.Admin().GetFromJsonAsync<CaStatusResponse>("/v1/ca/status", Ct))!.IsInitialized);

        var response = await RenewAsync(host, old.Id);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var renewed = (await response.Content.ReadFromJsonAsync<CreateIntermediateResponse>(Ct))!;
        Assert.True(renewed.Issuer.IsDefault);
        Assert.NotNull((await RowAsync(host, old.Id)).RevokedAtUtc);
        Assert.True((await host.Admin().GetFromJsonAsync<CaStatusResponse>("/v1/ca/status", Ct))!.IsInitialized);
    }

    [Fact]
    public async Task WhatCannotBeRenewed_IsRefused_AndNothingIsWritten()
    {
        await using var host = new IssuerApiHost();
        var root = await OnlineRootAsync(host);
        var pending = await OnlineIntermediateAsync(host, root.Id, "Pending", makeDefault: false);
        await ChangeAsync(host, pending.Id, i => i.Status = IssuerStatus.PendingCertificate);
        var archived = await OnlineIntermediateAsync(host, root.Id, "Archived", makeDefault: false);
        await ChangeAsync(host, archived.Id, i => i.Status = IssuerStatus.Archived);
        var retired = await OnlineIntermediateAsync(host, root.Id, "Retired", makeDefault: false);
        await ChangeAsync(host, retired.Id, i => i.Status = IssuerStatus.Retired);
        var offline = await OnlineIntermediateAsync(host, root.Id, "Offline", makeDefault: false);
        await ChangeAsync(host, offline.Id, i => i.KeyCustody = IssuerKeyCustody.Offline);
        var count = await IssuerCountAsync(host);

        Assert.Equal(HttpStatusCode.Conflict, (await RenewAsync(host, root.Id)).StatusCode);
        foreach (var id in new[] { pending.Id, archived.Id, retired.Id, offline.Id })
            Assert.Equal(HttpStatusCode.Conflict, (await RenewAsync(host, id)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await RenewAsync(host, new IssuerId(Guid.NewGuid()))).StatusCode);
        Assert.Equal(count, await IssuerCountAsync(host));
    }

    [Fact]
    public async Task UnderARevokedParent_TheRenewalIsRefused()
    {
        await using var host = new IssuerApiHost();
        var root = await OnlineRootAsync(host);
        var old = await OnlineIntermediateAsync(host, root.Id);
        await RevokeAsync(host, root.Id);

        var response = await RenewAsync(host, old.Id);

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.Contains("parent", (await response.Content.ReadFromJsonAsync<ProblemDetails>(Ct))!.Detail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task StrengthEnforcedSinceCreation_RefusesTheRenewal()
    {
        await using var host = new IssuerApiHost();
        var root = await OnlineRootAsync(host, CertificateKeyAlgorithm.MlDsa44);
        await SettingsAsync(host, s => { s.PqcStage = PqcStage.Off; s.IssuerStrengthMode = IssuerStrengthMode.Warn; });
        var old = await OnlineIntermediateAsync(host, root.Id, algorithm: CertificateKeyAlgorithm.MlDsa87);
        await SettingsAsync(host, s => s.IssuerStrengthMode = IssuerStrengthMode.Enforce);
        var count = await IssuerCountAsync(host);

        Assert.Equal(HttpStatusCode.BadRequest, (await RenewAsync(host, old.Id)).StatusCode);
        Assert.Equal(count, await IssuerCountAsync(host));
    }

    [Fact]
    public async Task RenewingTwice_TheSecondIsRefused()
    {
        await using var host = new IssuerApiHost();
        var externalRoot = CaCertificateBuilderTests.Root(CertificateKeyAlgorithm.EcdsaP256);
        var created = await IssuerCeremonyTestSteps.PendingAsync(host);
        (await IssuerCeremonyTestSteps.InstallAsync(host, created.Issuer.Id,
            IssuerCeremonyTestSteps.Sign(externalRoot, created.RequestFile!), externalRoot.Cert)).EnsureSuccessStatusCode();

        Assert.Equal(HttpStatusCode.Created, (await RenewAsync(host, created.Issuer.Id)).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await RenewAsync(host, created.Issuer.Id)).StatusCode);

        await using var db = host.Kit.Database.CreateContext();
        Assert.Equal(1, await db.Issuers.CountAsync(i => i.RenewalOfIssuerId == created.Issuer.Id, Ct));
    }

    [Fact]
    public async Task ValidityPastTheParent_IsCappedAtTheParent()
    {
        await using var host = new IssuerApiHost();
        var root = await OnlineRootAsync(host);
        var old = await OnlineIntermediateAsync(host, root.Id);

        var response = await RenewAsync(host, old.Id, validityDays: 36500);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var renewed = (await response.Content.ReadFromJsonAsync<CreateIntermediateResponse>(Ct))!;
        Assert.True(renewed.Issuer.ValidTo <= (await RowAsync(host, root.Id)).ValidTo);
    }

    [Fact]
    public async Task WithTwoPersonApproval_ARenewalNeedsAGrant()
    {
        await using var host = new IssuerApiHost();
        var root = await OnlineRootAsync(host);
        var old = await OnlineIntermediateAsync(host, root.Id);
        await SettingsAsync(host, s => s.RequireTwoPersonApproval = true);
        var count = await IssuerCountAsync(host);

        var response = await RenewAsync(host, old.Id);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("Approval required", (await response.Content.ReadFromJsonAsync<ProblemDetails>(Ct))!.Title);
        Assert.Equal(count, await IssuerCountAsync(host));
    }

    private static async Task<IssuerId> OfflineIntermediateAsync(IssuerApiHost host,
        (Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair Key, Org.BouncyCastle.X509.X509Certificate Cert) root)
    {
        var created = await IssuerCeremonyTestSteps.PendingAsync(host);
        (await IssuerCeremonyTestSteps.InstallAsync(host, created.Issuer.Id,
            IssuerCeremonyTestSteps.Sign(root, created.RequestFile!), root.Cert)).EnsureSuccessStatusCode();
        return created.Issuer.Id;
    }

    private static async Task<CreateIntermediateResponse> PendingRenewalAsync(IssuerApiHost host, IssuerId old)
    {
        var response = await RenewAsync(host, old);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var pending = (await response.Content.ReadFromJsonAsync<CreateIntermediateResponse>(Ct))!;
        Assert.NotNull(pending.RequestFile);
        Assert.Equal(IssuerStatus.PendingCertificate, pending.Issuer.Status);
        return pending;
    }

    [Fact]
    public async Task OfflineParent_RenewalWaitsForInstall_ThenSwaps()
    {
        await using var host = new IssuerApiHost();
        var root = CaCertificateBuilderTests.Root(CertificateKeyAlgorithm.EcdsaP256);
        var old = await OfflineIntermediateAsync(host, root);

        var pending = await PendingRenewalAsync(host, old);
        Assert.Equal(IssuerStatus.Active, (await RowAsync(host, old)).Status);
        Assert.True((await RowAsync(host, old)).IsDefault);

        var installed = await IssuerCeremonyTestSteps.InstallAsync(host, pending.Issuer.Id,
            IssuerCeremonyTestSteps.Sign(root, pending.RequestFile!), root.Cert);

        Assert.True(installed.IsSuccessStatusCode, await installed.Content.ReadAsStringAsync(Ct));
        var replacement = await RowAsync(host, pending.Issuer.Id);
        Assert.Equal(IssuerStatus.Active, replacement.Status);
        Assert.True(replacement.IsDefault);
        Assert.Equal((await RowAsync(host, old)).Name, replacement.Name);
        Assert.Equal(IssuerStatus.Retired, (await RowAsync(host, old)).Status);
    }

    [Fact]
    public async Task ImportedExternalIntermediate_RenewsThroughTheRoundTrip_AndKeepsItsIssuer()
    {
        await using var host = new IssuerApiHost();
        var root = CaCertificateBuilderTests.Root(CertificateKeyAlgorithm.EcdsaP256, "External Root");
        var key = Qertum.Services.Crypto.AlgorithmStrategyFactory.CreateIssuer(CertificateKeyAlgorithm.EcdsaP256)
            .GenerateCaKeyPair(new Org.BouncyCastle.Security.SecureRandom());
        var intermediate = CaCertificateBuilder.IssueSubordinate(new LocalKeyPairCaSigner(root.Key), root.Cert,
            QertumKeyCodec.ToSubjectPublicKeyInfo(key.Public), new Org.BouncyCastle.Asn1.X509.X509Name("CN=External Issuing CA"),
            new SubordinateCaProfile(0, [], [], [], []), DateTime.UtcNow.AddMinutes(-5), DateTime.UtcNow.AddDays(300));
        (await host.Admin().PostAsJsonAsync("/v1/ca/import", new ImportCaRequest
        {
            CertificatePem = QertumKeyCodec.WriteCertificatePem(intermediate),
            PrivateKeyPem = QertumKeyCodec.WritePrivateKeyPem(key.Private)
        }, Ct)).EnsureSuccessStatusCode();
        var old = await host.DefaultIssuerIdAsync(Ct);
        Assert.Equal(IssuerKind.Intermediate, (await RowAsync(host, old)).Kind);

        var pending = await PendingRenewalAsync(host, old);
        var otherRoot = CaCertificateBuilderTests.Root(CertificateKeyAlgorithm.EcdsaP256, "Other Root");
        var wrong = await IssuerCeremonyTestSteps.InstallAsync(host, pending.Issuer.Id,
            IssuerCeremonyTestSteps.Sign(otherRoot, pending.RequestFile!), otherRoot.Cert);
        Assert.Equal(HttpStatusCode.BadRequest, wrong.StatusCode);
        Assert.Contains("issuer", (await wrong.Content.ReadFromJsonAsync<ProblemDetails>(Ct))!.Detail, StringComparison.OrdinalIgnoreCase);

        var installed = await IssuerCeremonyTestSteps.InstallAsync(host, pending.Issuer.Id,
            IssuerCeremonyTestSteps.Sign(root, pending.RequestFile!, notAfter: DateTime.UtcNow.AddDays(200)), root.Cert);
        Assert.True(installed.IsSuccessStatusCode, await installed.Content.ReadAsStringAsync(Ct));
        Assert.True((await RowAsync(host, pending.Issuer.Id)).IsDefault);
        Assert.Equal(IssuerStatus.Retired, (await RowAsync(host, old)).Status);
    }

    [Fact]
    public async Task OldRevokedWhileRenewalPending_InstallStillSwaps()
    {
        await using var host = new IssuerApiHost();
        var root = CaCertificateBuilderTests.Root(CertificateKeyAlgorithm.EcdsaP256);
        var old = await OfflineIntermediateAsync(host, root);
        var pending = await PendingRenewalAsync(host, old);
        await RevokeAsync(host, old);

        var installed = await IssuerCeremonyTestSteps.InstallAsync(host, pending.Issuer.Id,
            IssuerCeremonyTestSteps.Sign(root, pending.RequestFile!), root.Cert);

        Assert.True(installed.IsSuccessStatusCode, await installed.Content.ReadAsStringAsync(Ct));
        Assert.True((await RowAsync(host, pending.Issuer.Id)).IsDefault);
        Assert.True((await host.Admin().GetFromJsonAsync<CaStatusResponse>("/v1/ca/status", Ct))!.IsInitialized);
    }

    [Fact]
    public async Task PendingRenewalDeleted_LeavesTheOldAlone_AndRenewWorksAgain()
    {
        await using var host = new IssuerApiHost();
        var root = CaCertificateBuilderTests.Root(CertificateKeyAlgorithm.EcdsaP256);
        var old = await OfflineIntermediateAsync(host, root);
        var pending = await PendingRenewalAsync(host, old);

        Assert.Equal(HttpStatusCode.NoContent, (await host.Admin().DeleteAsync($"/v1/issuers/{pending.Issuer.Id}", Ct)).StatusCode);

        var kept = await RowAsync(host, old);
        Assert.Equal(IssuerStatus.Active, kept.Status);
        Assert.True(kept.IsDefault);
        await PendingRenewalAsync(host, old);
    }

    [Fact]
    public async Task OldArchivedMeanwhile_InstallIsRefused()
    {
        await using var host = new IssuerApiHost();
        var root = CaCertificateBuilderTests.Root(CertificateKeyAlgorithm.EcdsaP256);
        var old = await OfflineIntermediateAsync(host, root);
        var pending = await PendingRenewalAsync(host, old);
        await ChangeAsync(host, old, i => { i.Status = IssuerStatus.Archived; i.IsDefault = false; });

        var installed = await IssuerCeremonyTestSteps.InstallAsync(host, pending.Issuer.Id,
            IssuerCeremonyTestSteps.Sign(root, pending.RequestFile!), root.Cert);

        Assert.Equal(HttpStatusCode.Conflict, installed.StatusCode);
        Assert.Equal(IssuerStatus.PendingCertificate, (await RowAsync(host, pending.Issuer.Id)).Status);
    }

    [Fact]
    public async Task AChildRenewsUnderItsRenewedParent()
    {
        await using var host = new IssuerApiHost();
        var root = await OnlineRootAsync(host);
        var a = await OnlineIntermediateAsync(host, root.Id, "A", makeDefault: false, pathLength: 1);
        var b = await OnlineIntermediateAsync(host, a.Id, "B");
        var renewedA = (await (await RenewAsync(host, a.Id)).Content.ReadFromJsonAsync<CreateIntermediateResponse>(Ct))!.Issuer;

        var response = await RenewAsync(host, b.Id);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(renewedA.Id, (await response.Content.ReadFromJsonAsync<CreateIntermediateResponse>(Ct))!.Issuer.ParentIssuerId);
    }

    [Fact]
    public async Task CaStatus_NamesTheKindOfTheRevokedIssuer()
    {
        await using var host = new IssuerApiHost();
        var root = await OnlineRootAsync(host);
        var old = await OnlineIntermediateAsync(host, root.Id);
        Assert.Null((await host.Admin().GetFromJsonAsync<CaStatusResponse>("/v1/ca/status", Ct))!.RevokedIssuerKind);

        await RevokeAsync(host, old.Id);
        await ChangeAsync(host, root.Id, i => i.IsDefault = false);

        Assert.Equal(IssuerKind.Intermediate, (await host.Admin().GetFromJsonAsync<CaStatusResponse>("/v1/ca/status", Ct))!.RevokedIssuerKind);
    }

    [Fact]
    public async Task AParentRenewedTwice_TheChildRenewsUnderTheNewest()
    {
        await using var host = new IssuerApiHost();
        var root = await OnlineRootAsync(host);
        var p = await OnlineIntermediateAsync(host, root.Id, "P", makeDefault: false, pathLength: 1);
        var c = await OnlineIntermediateAsync(host, p.Id, "C");
        var p1 = (await (await RenewAsync(host, p.Id)).Content.ReadFromJsonAsync<CreateIntermediateResponse>(Ct))!.Issuer;
        var p2 = (await (await RenewAsync(host, p1.Id)).Content.ReadFromJsonAsync<CreateIntermediateResponse>(Ct))!.Issuer;

        var response = await RenewAsync(host, c.Id);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(p2.Id, (await response.Content.ReadFromJsonAsync<CreateIntermediateResponse>(Ct))!.Issuer.ParentIssuerId);
    }

    [Fact]
    public async Task CaStatus_AfterARootHardStop_NamesTheRootNotItsIntermediate()
    {
        await using var host = new IssuerApiHost();
        var root = await OnlineRootAsync(host);
        var child = await OnlineIntermediateAsync(host, root.Id);
        var at = DateTime.UtcNow;
        await ChangeAsync(host, child.Id, i => { i.RevokedAtUtc = at.AddSeconds(1); i.Status = IssuerStatus.Retired; i.IsDefault = false; });
        await ChangeAsync(host, root.Id, i => { i.RevokedAtUtc = at; i.Status = IssuerStatus.Retired; i.IsDefault = false; });

        Assert.Equal(IssuerKind.Root, (await host.Admin().GetFromJsonAsync<CaStatusResponse>("/v1/ca/status", Ct))!.RevokedIssuerKind);
    }

    [Fact]
    public async Task ARenewedIntermediate_RevokedLater_CannotBeRenewedASecondTime()
    {
        await using var host = new IssuerApiHost();
        var root = await OnlineRootAsync(host);
        var old = await OnlineIntermediateAsync(host, root.Id);
        Assert.Equal(HttpStatusCode.OK, (await RenewAsync(host, old.Id)).StatusCode);
        await RevokeAsync(host, old.Id);

        var again = await RenewAsync(host, old.Id);

        Assert.Equal(HttpStatusCode.Conflict, again.StatusCode);
        Assert.Contains("already renewed", (await again.Content.ReadFromJsonAsync<ProblemDetails>(Ct))!.Detail);
        await using var db = host.Kit.Database.CreateContext();
        Assert.Equal(1, await db.Issuers.CountAsync(i => i.RenewalOfIssuerId == old.Id, Ct));
    }

    [Fact]
    public async Task TwoRenewalsAtOnce_LeaveExactlyOneReplacement()
    {
        await using var host = new IssuerApiHost();
        var root = await OnlineRootAsync(host);
        var old = await OnlineIntermediateAsync(host, root.Id);

        var responses = await Task.WhenAll(RenewAsync(host, old.Id), RenewAsync(host, old.Id));

        Assert.Contains(responses, r => r.StatusCode == HttpStatusCode.OK);
        Assert.All(responses, r => Assert.True(r.StatusCode is HttpStatusCode.OK or HttpStatusCode.Conflict, r.StatusCode.ToString()));
        await using var db = host.Kit.Database.CreateContext();
        Assert.Equal(1, await db.Issuers.CountAsync(i => i.RenewalOfIssuerId == old.Id, Ct));
        Assert.Equal(1, await db.Issuers.CountAsync(i => i.IsDefault, Ct));
    }

    [Fact]
    public async Task AnIssuerThatNeverGotACertificate_IsNotRenewed()
    {
        await using var host = new IssuerApiHost();
        var root = await OnlineRootAsync(host);
        var old = await OnlineIntermediateAsync(host, root.Id, makeDefault: false);
        await ChangeAsync(host, old.Id, i => { i.CertificatePem = null; i.RevokedAtUtc = DateTime.UtcNow; i.Status = IssuerStatus.Retired; });

        Assert.Equal(HttpStatusCode.Conflict, (await RenewAsync(host, old.Id)).StatusCode);
    }

    [Fact]
    public async Task TheRetiredWebhook_CarriesTheOldIssuersNewStatus()
    {
        var webhooks = new NullWebhooks();
        await using var host = new IssuerApiHost(services =>
        {
            services.RemoveAll<IWebhookService>();
            services.AddSingleton<IWebhookService>(webhooks);
        });
        var root = await OnlineRootAsync(host);
        var old = await OnlineIntermediateAsync(host, root.Id);

        Assert.Equal(HttpStatusCode.OK, (await RenewAsync(host, old.Id)).StatusCode);

        var retired = Assert.Single(webhooks.Events, e => e.EventType == WellKnownWebhookEvents.IssuerRetired);
        Assert.Equal("Retired", retired.Fields!["status"]);
    }
}
