using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Services.Policies;
using Qertum.Services.Validators;

namespace Qertum.Tests.Policies;

/// <summary>
/// Where a signing + encryption pair must be refused because one of its certificates cannot sign:
/// under a <c>KeyCertSign</c> template and as a CA key. Everywhere else it is an ordinary
/// post-quantum request, S/MIME included.
/// </summary>
public sealed class PairGuardRailTests
{
    private const string Actor = "alice";

    private static CertificateRequest Request(string type, CertificateKeyAlgorithm algorithm, string cn = "pair.example.test") =>
        new() { CommonName = cn, RequestedBy = Actor, Type = type, KeyAlgorithm = algorithm };

    private static CertificateTemplate Template(string keyUsages, bool linked = false) => new()
    {
        TypeKey = "Custom",
        KeyUsagesJson = keyUsages,
        IssuancePolicyId = linked ? new IssuancePolicyId(Guid.NewGuid()) : null
    };

    private static IssuancePolicyVersion UnrestrictedVersion() => new()
    {
        VersionNumber = 1,
        Status = IssuancePolicyVersionStatus.Published
    };

    public static TheoryData<CertificateKeyAlgorithm> Pairs => new()
    {
        CertificateKeyAlgorithm.PairMlDsa44MlKem512,
        CertificateKeyAlgorithm.PairMlDsa65MlKem768,
        CertificateKeyAlgorithm.PairMlDsa87MlKem1024
    };

    [Theory]
    [MemberData(nameof(Pairs))]
    public void Evaluator_RefusesAPairUnderACertSignTemplate_WithTheWordingOfAPair(CertificateKeyAlgorithm algorithm)
    {
        var decision = new IssuancePolicyEvaluator().Evaluate(
            Request("Custom", algorithm),
            Template("""["DigitalSignature","KeyCertSign","CrlSign"]"""),
            null, null, new CaSettings { PqcStage = PqcStage.Off });

        Assert.False(decision.Allowed);
        var violation = Assert.Single(decision.Violations);
        Assert.Equal(PolicyRules.KeyCapability, violation.Rule);
        Assert.Equal(algorithm.ToCanonicalString(), violation.Value);
        Assert.Contains("encryption-only", violation.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("key encapsulation key and cannot sign", violation.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("""["DigitalSignature","NonRepudiation","KeyEncipherment"]""")]
    [InlineData("""["DigitalSignature"]""")]
    public void Evaluator_AdmitsAPairUnderAnyOtherTemplate(string keyUsages)
    {
        var decision = new IssuancePolicyEvaluator().Evaluate(
            Request("Custom", CertificateKeyAlgorithm.PairMlDsa65MlKem768),
            Template(keyUsages), null, null, new CaSettings { PqcStage = PqcStage.Off });

        Assert.True(decision.Allowed);
    }

    [Fact]
    public void Evaluator_RefusesAPair_WhenThePolicyRequiresAClientGeneratedKey()
    {
        // A pair is always CA-generated, as ML-KEM is; no CSR can carry it.
        var version = UnrestrictedVersion();
        version.KeyCustody = KeyCustodyMode.RequireClientGenerated;

        var decision = new IssuancePolicyEvaluator().Evaluate(
            Request("Custom", CertificateKeyAlgorithm.PairMlDsa65MlKem768),
            Template("""["DigitalSignature"]""", linked: true),
            new IssuancePolicy { Name = "corp" }, version, new CaSettings { PqcStage = PqcStage.Off });

        Assert.Contains(decision.Violations, v => v.Rule == PolicyRules.KeyCustody);
    }

    [Fact]
    public void Evaluator_RefusesAPair_WhenAnAllowedAlgorithmsListDoesNotNameIt()
    {
        var version = UnrestrictedVersion();
        version.AllowedKeyAlgorithmsJson = """["ML-DSA-65"]""";

        var decision = new IssuancePolicyEvaluator().Evaluate(
            Request("Custom", CertificateKeyAlgorithm.PairMlDsa65MlKem768),
            Template("""["DigitalSignature"]""", linked: true),
            new IssuancePolicy { Name = "corp" }, version, new CaSettings { PqcStage = PqcStage.Off });

        Assert.Contains(decision.Violations, v => v.Rule == PolicyRules.KeyAlgorithm);

        version.AllowedKeyAlgorithmsJson = """["PAIR-ML-DSA-65-ML-KEM-768"]""";
        var listed = new IssuancePolicyEvaluator().Evaluate(
            Request("Custom", CertificateKeyAlgorithm.PairMlDsa65MlKem768),
            Template("""["DigitalSignature"]""", linked: true),
            new IssuancePolicy { Name = "corp" }, version, new CaSettings { PqcStage = PqcStage.Off });
        Assert.DoesNotContain(listed.Violations, v => v.Rule == PolicyRules.KeyAlgorithm);
    }

    // A row written past the create path is still stopped at approval and again before signing.
    [Fact]
    public async Task ApprovalAndThePreSigningCheck_RefuseAPairSubordinateCaAlreadyOnRecord()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var service = scope.CreateRequestService();
        var pending = Request("SubordinateCA", CertificateKeyAlgorithm.PairMlDsa65MlKem768, "pending.example.test");
        var approved = Request("SubordinateCA", CertificateKeyAlgorithm.PairMlDsa65MlKem768, "approved.example.test");
        approved.Status = CertificateRequestStatus.Approved;
        scope.Db.CertificateRequests.AddRange(pending, approved);
        await scope.Db.SaveChangesAsync(ct);

        var ex = await Assert.ThrowsAsync<IssuancePolicyViolationException>(() => service.MarkAsApprovedAsync(pending.Id, "approver", ct));
        Assert.Equal(PolicyEnforcementStage.Approval, ex.Stage);

        var claimed = await service.DequeueNextApprovedAsync(ct);
        Assert.Equal(approved.Id, claimed?.Id);
        var decision = await service.CheckIssuancePolicyAsync(approved.Id, ct);

        Assert.False(decision.Allowed);
        var stored = await scope.Db.CertificateRequests.AsNoTracking().SingleAsync(r => r.Id == approved.Id, ct);
        Assert.Equal(CertificateRequestStatus.Rejected, stored.Status);
    }

    [Fact]
    public async Task Create_RefusesAPairSubordinateCa_AndWritesNoRow()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);

        var ex = await Assert.ThrowsAsync<IssuancePolicyViolationException>(() =>
            scope.CreateRequestService().CreateAsync(Request("SubordinateCA", CertificateKeyAlgorithm.PairMlDsa87MlKem1024), Actor, ct));

        Assert.Equal(PolicyEnforcementStage.Create, ex.Stage);
        Assert.False(await scope.Db.CertificateRequests.AnyAsync(ct));
    }

    [Fact]
    public async Task Create_AdmitsAPairSmimeRequest_AtTheDefaultEnforceStage()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);

        var created = await scope.CreateRequestService().CreateAsync(Request("SMIME", CertificateKeyAlgorithm.PairMlDsa65MlKem768), Actor, ct);

        Assert.Equal(CertificateRequestStatus.Pending, created.Status);
        Assert.Equal(CertificateKeyAlgorithm.PairMlDsa65MlKem768, created.KeyAlgorithm);
    }

    [Fact]
    public async Task Preview_ReportsTheKeyCapabilityViolation_ForAPairUnderACaTemplate()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);

        var preview = await scope.CreatePreviewService().PreviewCreateAsync(
            Request("SubordinateCA", CertificateKeyAlgorithm.PairMlDsa44MlKem512), ct);

        Assert.False(preview.Allowed);
        Assert.Contains(preview.Violations, v => v.Rule == PolicyRules.KeyCapability);
    }

    [Theory]
    [MemberData(nameof(Pairs))]
    public void CaValidators_RefuseAPairAsACaKey_NamingThePair(CertificateKeyAlgorithm algorithm)
    {
        var root = new GenerateCaRequestValidator().Validate(
            new GenerateCaRequest { CommonName = "Root", KeyAlgorithm = algorithm, ValidityDays = 365 });
        var intermediate = new CreateIntermediateRequestValidator().Validate(
            new CreateIntermediateRequest { Name = "Issuing", CommonName = "Issuing", KeyAlgorithm = algorithm, ValidityDays = 365 });

        var rootError = Assert.Single(root.Errors, e => e.PropertyName == nameof(GenerateCaRequest.KeyAlgorithm));
        Assert.Contains("pair", rootError.ErrorMessage, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("key encapsulation key cannot sign", rootError.ErrorMessage, StringComparison.Ordinal);
        Assert.Contains(intermediate.Errors, e => e.PropertyName == nameof(CreateIntermediateRequest.KeyAlgorithm));
    }
}
