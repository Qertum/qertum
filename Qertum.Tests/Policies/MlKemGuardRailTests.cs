using Microsoft.EntityFrameworkCore;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Qertum.Services;
using Qertum.Services.Crypto;
using Qertum.Services.Policies;
using Qertum.Services.Validators;

namespace Qertum.Tests.Policies;

/// <summary>
/// Where an ML-KEM key must be refused because the certificate would have to sign: under a
/// <c>KeyCertSign</c> template (a subordinate CA), as a generated root, and as an imported root.
/// Everywhere else it is an ordinary post-quantum subject key, PQC-only included.
/// </summary>
public sealed class MlKemGuardRailTests
{
    private const string Actor = "alice";

    private static CertificateRequest Request(string type, CertificateKeyAlgorithm algorithm, string cn = "kem.example.test") =>
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

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Evaluator_RefusesAKemKeyUnderACertSignTemplate_LinkedOrNot(bool linked)
    {
        var decision = new IssuancePolicyEvaluator().Evaluate(
            Request("Custom", CertificateKeyAlgorithm.MlKem768),
            Template("""["DigitalSignature","KeyCertSign","CrlSign"]""", linked),
            linked ? new IssuancePolicy { Name = "corp" } : null,
            linked ? UnrestrictedVersion() : null,
            new CaSettings { PqcStage = PqcStage.Off });

        Assert.False(decision.Allowed);
        var violation = Assert.Single(decision.Violations);
        Assert.Equal(PolicyRules.KeyCapability, violation.Rule);
        Assert.Equal("ML-KEM-768", violation.Value);
    }

    [Theory]
    [InlineData(CertificateKeyAlgorithm.MlKem768, """["KeyEncipherment"]""")]
    [InlineData(CertificateKeyAlgorithm.MlKem768, """["DigitalSignature","KeyEncipherment"]""")]
    [InlineData(CertificateKeyAlgorithm.MlDsa65, """["DigitalSignature","KeyCertSign","CrlSign"]""")]
    [InlineData(CertificateKeyAlgorithm.Rsa, """["DigitalSignature","KeyCertSign","CrlSign"]""")]
    public void Evaluator_AdmitsEveryOtherCombination(CertificateKeyAlgorithm algorithm, string keyUsages)
    {
        var decision = new IssuancePolicyEvaluator().Evaluate(
            Request("Custom", algorithm), Template(keyUsages), null, null, new CaSettings { PqcStage = PqcStage.Off });

        Assert.True(decision.Allowed);
    }

    [Fact]
    public async Task Create_RefusesAnMlKemSubordinateCaAndWritesNoRow()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);

        var ex = await Assert.ThrowsAsync<IssuancePolicyViolationException>(() =>
            scope.CreateRequestService().CreateAsync(Request("SubordinateCA", CertificateKeyAlgorithm.MlKem1024), Actor, ct));

        Assert.Equal(PolicyEnforcementStage.Create, ex.Stage);
        Assert.False(await scope.Db.CertificateRequests.AnyAsync(ct));
    }

    [Fact]
    public async Task Create_AdmitsAnMlKemSmimeCertificate()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);

        var created = await scope.CreateRequestService().CreateAsync(Request("SMIME", CertificateKeyAlgorithm.MlKem768), Actor, ct);

        Assert.Equal(CertificateRequestStatus.Pending, created.Status);
        Assert.Equal(CertificateKeyAlgorithm.MlKem768, created.KeyAlgorithm);
    }

    // A row filed before the rule existed (or written past the create path) is still stopped at
    // approval and again before signing.
    [Fact]
    public async Task ApprovalAndThePreSigningCheck_RefuseAnMlKemSubordinateCaAlreadyOnRecord()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var service = scope.CreateRequestService();
        var pending = Request("SubordinateCA", CertificateKeyAlgorithm.MlKem768, "pending.example.test");
        var approved = Request("SubordinateCA", CertificateKeyAlgorithm.MlKem768, "approved.example.test");
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
    public async Task Preview_ReportsTheKeyCapabilityViolation()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);

        var preview = await scope.CreatePreviewService().PreviewCreateAsync(
            Request("SubordinateCA", CertificateKeyAlgorithm.MlKem512), ct);

        Assert.False(preview.Allowed);
        Assert.Contains(preview.Violations, v => v.Rule == PolicyRules.KeyCapability);
    }

    [Theory]
    [InlineData(CertificateKeyAlgorithm.MlKem512)]
    [InlineData(CertificateKeyAlgorithm.MlKem768)]
    [InlineData(CertificateKeyAlgorithm.MlKem1024)]
    [InlineData(CertificateKeyAlgorithm.HybridEcdsaP256)]
    [InlineData(CertificateKeyAlgorithm.HybridEcdsaP384)]
    public void GenerateCaValidator_RefusesAlgorithmsThatCannotBeACaKey(CertificateKeyAlgorithm algorithm)
    {
        var result = new GenerateCaRequestValidator().Validate(
            new GenerateCaRequest { CommonName = "Root", KeyAlgorithm = algorithm, ValidityDays = 365 });

        Assert.Contains(result.Errors, e => e.PropertyName == nameof(GenerateCaRequest.KeyAlgorithm));
    }

    [Theory]
    [InlineData(null)]
    [InlineData(CertificateKeyAlgorithm.Rsa)]
    [InlineData(CertificateKeyAlgorithm.MlDsa44)]
    [InlineData(CertificateKeyAlgorithm.SlhDsaSha2128f)]
    [InlineData(CertificateKeyAlgorithm.MlDsa65EcdsaP256Sha512)]
    public void GenerateCaValidator_AdmitsEveryIssuerAlgorithm(CertificateKeyAlgorithm? algorithm)
    {
        var result = new GenerateCaRequestValidator().Validate(
            new GenerateCaRequest { CommonName = "Root", KeyAlgorithm = algorithm, ValidityDays = 365 });

        Assert.True(result.IsValid, string.Join("; ", result.Errors));
    }

    // Detection alone would accept this certificate: the refusal has to name the reason rather than
    // leave the import to fail on an unrelated private-key check.
    [Fact]
    public void ImportPolicy_RefusesACaCertificateWhoseKeyIsMlKem()
    {
        var result = ApiEndpointMappings.ValidateImportAlgorithmPolicy(new CaSettings { PqcStage = PqcStage.Off }, KemKeyedCaCertificatePem());

        var problem = Assert.IsAssignableFrom<Microsoft.AspNetCore.Http.IStatusCodeHttpResult>(result);
        Assert.Equal(400, problem.StatusCode);
    }

    [Theory]
    [InlineData(CertificateKeyAlgorithm.MlKem512)]
    [InlineData(CertificateKeyAlgorithm.MlKem768)]
    [InlineData(CertificateKeyAlgorithm.MlKem1024)]
    public void PqcOnly_AdmitsMlKem(CertificateKeyAlgorithm algorithm) =>
        Assert.True(PqcStageEvaluator.IsCompliant(algorithm));

    /// <summary>A CA-shaped certificate carrying an ML-KEM key, signed by a throwaway ECDSA key.</summary>
    private static string KemKeyedCaCertificatePem()
    {
        var random = new SecureRandom();
        var kem = new MLKemKeyPairGenerator();
        kem.Init(new MLKemKeyGenerationParameters(random, MLKemParameters.ml_kem_768));
        var ec = new ECKeyPairGenerator();
        ec.Init(new ECKeyGenerationParameters(Org.BouncyCastle.Asn1.Sec.SecObjectIdentifiers.SecP256r1, random));
        var signer = ec.GenerateKeyPair();

        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(new BigInteger(64, random));
        generator.SetIssuerDN(new X509Name("CN=KEM Root"));
        generator.SetSubjectDN(new X509Name("CN=KEM Root"));
        generator.SetNotBefore(DateTime.UtcNow.AddMinutes(-1));
        generator.SetNotAfter(DateTime.UtcNow.AddDays(30));
        generator.SetSubjectPublicKeyInfo(QertumKeyCodec.ToSubjectPublicKeyInfo(kem.GenerateKeyPair().Public));
        generator.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
        return QertumKeyCodec.WriteCertificatePem(generator.Generate(QertumKeyCodec.SignatureFactoryFor(signer.Private)));
    }
}
