using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging.Abstractions;
using Qertum.Services;
using Qertum.Services.Est;
using Xunit;
using CertificateRequest = Qertum.Services.CertificateRequest;

namespace Qertum.Tests;

/// <summary>
/// Minimal <see cref="ICertificateRequestService"/> fake implementing only
/// <see cref="GetRevocationStatusesAsync"/>, patterned on the fakes in
/// <c>CertificateRequestQueueConsumerTests.cs</c>. Every other member is unused by
/// <see cref="EstEndpointMappings.VerifyReenrollCertificateAsync"/> and throws if called.
/// </summary>
internal sealed class FakeRevocationStatusService(IReadOnlyDictionary<string, OcspCertificateStatus> statuses)
    : ICertificateRequestService
{
    public Task<IReadOnlyDictionary<string, OcspCertificateStatus>> GetRevocationStatusesAsync(
        IReadOnlyCollection<string> serialNumbers, CancellationToken cancellationToken = default)
        => Task.FromResult(statuses);

    public Task<PagedResult<CertificateRequest>> GetAllAsync(int page = 1, int pageSize = 100,
        CertificateRequestStatus? status = null, string? search = null, CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task<CertificateRequestStatusCounts> GetStatusCountsAsync(string? search = null, CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task<PagedResult<CertificateRequest>> GetIssuedAsync(int page = 1, int pageSize = 100,
        IssuedCertificateFilter? filter = null, string? search = null, CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task<IssuedCertificateCounts> GetIssuedValidityCountsAsync(string? search = null, CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task<PagedResult<CertificateRequest>> GetRejectedAsync(int page = 1, int pageSize = 100, CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task<PagedResult<CertificateRequest>> GetRevokedAsync(int page = 1, int pageSize = 100, CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task<PagedResult<CertificateRequest>> GetExpiredAsync(int page = 1, int pageSize = 100, CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task<IReadOnlyList<CertificateRequest>> GetAllRevokedForCrlAsync(CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task<IReadOnlyList<CertificateRequest>> GetRevokedSinceForCrlAsync(DateTime sinceUtc, CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task<CertificateRequest?> GetByIdAsync(CertificateRequestId id, CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task<CertificateRequest?> DequeueNextApprovedAsync(CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task<int> ResetStuckProcessingAsync(CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task<CertificateRequest> CreateAsync(CertificateRequest request, string performedBy, CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task<CertificateRequest?> MarkAsApprovedAsync(CertificateRequestId id, string performedBy, CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task<CertificateRequest> CreateAsync(CertificateRequest request, string performedBy, string? autoApprovalSetting, CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task<CertificateRequest> CreateAsync(CertificateRequest request, string performedBy, string? autoApprovalSetting, Qertum.Services.Policies.RequesterRoles? requester, CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task<CertificateRequest?> MarkAsApprovedAsync(CertificateRequestId id, string performedBy, Qertum.Services.Policies.ApprovalPreviewReport? previewReport, CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task<CertificateRequest?> MarkAsApprovedAsync(CertificateRequestId id, string performedBy, Qertum.Services.Policies.ApprovalPreviewReport? previewReport, Qertum.Services.Policies.CallerContext? caller, CancellationToken cancellationToken) => throw new NotImplementedException();
    public Task<CertificateRequest?> MarkAsAutoApprovedAsync(CertificateRequestId id, string performedBy, string autoApprovalSetting, CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task<CertificateRequest?> MarkAsRejectedAsync(CertificateRequestId id, string performedBy, CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task<CertificateRequest?> MarkAsRejectedWithReasonAsync(CertificateRequestId id, string? failureReason, string performedBy, CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task<CertificateRequest?> MarkAsIssuedAsync(CertificateRequestId id, GeneratedCertificate generatedData, string performedBy = "queue-consumer", CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task<Qertum.Services.Policies.PolicyDecision> CheckIssuancePolicyAsync(CertificateRequestId id, CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task<CertificateRequest?> MarkAsPendingRevocationAsync(CertificateRequestId id, string? reason, string performedBy, CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task<CertificateRequest?> DequeueNextPendingRevocationAsync(CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task<CertificateRequest?> MarkAsRevokedAsync(CertificateRequestId id, string? reason, string performedBy, CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task<CertificateRequest?> UpdateMetadataAsync(CertificateRequestId id, CertificateMetadata metadata, string performedBy, CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task<CertificateRequest?> RenewAsync(CertificateRequestId id, string performedBy, CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task<CertificateRequest?> RenewAsync(CertificateRequestId id, string performedBy, Qertum.Services.Policies.CallerContext? caller, CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task<CertificateRequest> CreateAsync(CertificateRequest request, string performedBy, string? autoApprovalSetting, Qertum.Services.Policies.RequesterRoles? requester, Qertum.Services.Policies.CallerContext? caller, CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task<CertificateRequest?> UpdateAsync(CertificateRequestId id, CertificateRequest request, string performedBy, Qertum.Services.Policies.RequesterRoles? requester, Qertum.Services.Policies.CallerContext? caller, CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task<IReadOnlyList<CertificateRequest>> GetCertsNeedingAutoRenewalAsync(int daysBeforeExpiry, CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task<CertificateRequest?> UpdateAsync(CertificateRequestId id, CertificateRequest request, string performedBy, CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task<CertificateRequest?> UpdateAsync(CertificateRequestId id, CertificateRequest request, string performedBy, Qertum.Services.Policies.RequesterRoles? requester, CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task<bool> DeleteAsync(CertificateRequestId id, string performedBy, CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task<CertificateDashboardSummary> GetDashboardSummaryAsync(CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task<CaSettings> GetSettingsAsync(CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task<CaSettings> SetPqcStageAsync(PqcStage stage, string performedBy, CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task<CaSettings> SetCaApprovalRuleAsync(bool requireIndependent, string performedBy, CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task<CaSettings> SetIssuerStrengthAsync(IssuerStrengthMode mode, string performedBy, CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task<CaSettings> SetRevokedIssuerModeAsync(RevokedIssuerMode mode, string performedBy, CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task<CaSettings> SetTwoPersonApprovalAsync(bool enabled, string performedBy, CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task<CaSettings> SetupOrUpdateSettingsAsync(CaSettings settings, string performedBy, CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task<long> ClaimNextCrlNumberAsync(CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task RecordBaseCrlAsync(long crlNumber, DateTime thisUpdateUtc, CancellationToken cancellationToken = default) => throw new NotImplementedException();
    public Task<Guid?> GetPendingRootCaRequestIdAsync(CancellationToken cancellationToken = default) => throw new NotImplementedException();
}

/// <summary>
/// Unit tests for <see cref="EstEndpointMappings.VerifyReenrollCertificateAsync"/>, testing the
/// verification logic directly rather than over HTTP: <c>WebApplicationFactory</c>'s in-memory
/// <c>TestServer</c> has no established way in this codebase to inject
/// <c>HttpContext.Connection.ClientCertificate</c> without a real TLS handshake (confirmed by
/// grepping <c>Qertum.Tests</c> for existing usage — none found), so the mTLS-authenticated paths
/// are covered here instead of via a full HTTP round trip.
/// </summary>
public sealed class EstReenrollVerificationTests : IDisposable
{
    private readonly CertificateGenerator _generator;
    private readonly string _caDataDir;
    private readonly X509Certificate2 _caCertificate;

    public EstReenrollVerificationTests()
    {
        _caDataDir = Path.Combine(Path.GetTempPath(), "CaData-" + Guid.NewGuid().ToString("N"));
        _generator = new CertificateGenerator(
            new EphemeralDataProtectionProvider(),
            new CaDataOptions { Directory = _caDataDir },
            NullLogger<CertificateGenerator>.Instance);

        _generator.GenerateCa(new GenerateCaRequest
        {
            CommonName = "EST Reenroll Test Root CA",
            KeyAlgorithm = CertificateKeyAlgorithm.Rsa,
            ValidityDays = 365
        });

        _caCertificate = X509Certificate2.CreateFromPem(_generator.GetCaCertificatePem());
    }

    public void Dispose()
    {
        _caCertificate.Dispose();
        if (Directory.Exists(_caDataDir))
            try { Directory.Delete(_caDataDir, recursive: true); } catch { /* best effort */ }
    }

    [Fact]
    public void InvolvesCompositeSignature_is_false_for_a_classical_leaf_under_a_classical_ca()
    {
        using var leaf = X509Certificate2.CreateFromPem(IssueLeaf("classical-reenroll.example.com").CertificatePem);

        Assert.False(EstEndpointMappings.InvolvesCompositeSignature(leaf, _caCertificate));
    }

    [Fact]
    public void InvolvesCompositeSignature_is_true_for_a_composite_leaf_or_a_composite_ca()
    {
        using var compositeLeaf = X509Certificate2.CreateFromPem(_generator.GenerateCertificate(
            new CertificateRequest { CommonName = "composite-reenroll.example.com", KeyAlgorithm = CertificateKeyAlgorithm.MlDsa65EcdsaP256Sha512 },
            new CaSettings { PqcStage = PqcStage.Off }).CertificatePem);
        Assert.True(EstEndpointMappings.InvolvesCompositeSignature(compositeLeaf, _caCertificate));

        var compositeCaDir = Path.Combine(Path.GetTempPath(), "CaData-" + Guid.NewGuid().ToString("N"));
        try
        {
            var compositeCa = new CertificateGenerator(new EphemeralDataProtectionProvider(),
                new CaDataOptions { Directory = compositeCaDir }, NullLogger<CertificateGenerator>.Instance);
            compositeCa.GenerateCa(new GenerateCaRequest
            {
                CommonName = "Composite EST Root", KeyAlgorithm = CertificateKeyAlgorithm.MlDsa65EcdsaP256Sha512, ValidityDays = 365
            });
            using var caCertificate = X509Certificate2.CreateFromPem(compositeCa.GetCaCertificatePem());
            using var classicalLeaf = X509Certificate2.CreateFromPem(compositeCa.GenerateCertificate(
                new CertificateRequest { CommonName = "ecdsa-under-composite.example.com", KeyAlgorithm = CertificateKeyAlgorithm.EcdsaP256 },
                new CaSettings { PqcStage = PqcStage.Off }).CertificatePem);

            // The leaf's own key is classical; the CA's signature over it is composite.
            Assert.True(EstEndpointMappings.InvolvesCompositeSignature(classicalLeaf, caCertificate));
        }
        finally
        {
            if (Directory.Exists(compositeCaDir))
                try { Directory.Delete(compositeCaDir, recursive: true); } catch { /* best effort */ }
        }
    }

    private GeneratedCertificate IssueLeaf(string commonName) =>
        _generator.GenerateCertificate(
            new CertificateRequest { CommonName = commonName, Type = "WebServer" },
            new CaSettings { PqcStage = PqcStage.Off, OrganizationName = "Test Org" });

    private GeneratedCertificate IssueLeaf(string commonName, params string[] dnsNames) =>
        _generator.GenerateCertificate(
            new CertificateRequest
            {
                CommonName = commonName,
                Type = "WebServer",
                PropertiesJson = System.Text.Json.JsonSerializer.Serialize(new { dnsNames })
            },
            new CaSettings { PqcStage = PqcStage.Off, OrganizationName = "Test Org" });

    [Fact]
    public void CsrIdentityMatchesCertificate_accepts_case_insensitive_dns_names_with_one_terminal_dot()
    {
        using var leaf = X509Certificate2.CreateFromPem(IssueLeaf(
            "device.example.test", "alt.example.test").CertificatePem);

        var matches = EstEndpointMappings.CsrIdentityMatchesCertificate(
            "DEVICE.EXAMPLE.TEST.", ["ALT.EXAMPLE.TEST."], leaf);

        Assert.True(matches);
    }

    [Fact]
    public void CsrIdentityMatchesCertificate_treats_a_wildcard_as_a_literal_dns_name()
    {
        using var leaf = X509Certificate2.CreateFromPem(IssueLeaf("*.example.test").CertificatePem);

        var matches = EstEndpointMappings.CsrIdentityMatchesCertificate(
            "host.example.test", [], leaf);

        Assert.False(matches);
    }

    [Fact]
    public void CsrIdentityMatchesCertificate_rejects_a_changed_common_name()
    {
        using var leaf = X509Certificate2.CreateFromPem(IssueLeaf("device.example.test").CertificatePem);

        var matches = EstEndpointMappings.CsrIdentityMatchesCertificate(
            "other.example.test", [], leaf);

        Assert.False(matches);
    }

    [Fact]
    public async Task VerifyReenrollCertificateAsync_accepts_a_still_issued_certificate()
    {
        var ct = TestContext.Current.CancellationToken;
        var issued = IssueLeaf("reenroll-good.example.com");
        using var leaf = X509Certificate2.CreateFromPem(issued.CertificatePem);

        var normalizedSerial = EstEndpointMappings.NormalizeSerial(leaf.SerialNumber);
        var statuses = new Dictionary<string, OcspCertificateStatus>
        {
            [normalizedSerial] = OcspCertificateStatus.Good
        };
        var fakeService = new FakeRevocationStatusService(statuses);

        var result = await EstEndpointMappings.VerifyReenrollCertificateAsync(leaf, _caCertificate, fakeService, ct);

        Assert.True(result);
    }

    [Fact]
    public async Task VerifyReenrollCertificateAsync_rejects_a_revoked_certificate()
    {
        var ct = TestContext.Current.CancellationToken;
        var issued = IssueLeaf("reenroll-revoked.example.com");
        using var leaf = X509Certificate2.CreateFromPem(issued.CertificatePem);

        var normalizedSerial = EstEndpointMappings.NormalizeSerial(leaf.SerialNumber);
        var statuses = new Dictionary<string, OcspCertificateStatus>
        {
            [normalizedSerial] = new(OcspCertificateState.Revoked, DateTime.UtcNow.AddMinutes(-5), "keyCompromise")
        };
        var fakeService = new FakeRevocationStatusService(statuses);

        var result = await EstEndpointMappings.VerifyReenrollCertificateAsync(leaf, _caCertificate, fakeService, ct);

        Assert.False(result);
    }

    [Fact]
    public async Task VerifyReenrollCertificateAsync_rejects_a_certificate_from_a_different_issuer()
    {
        var ct = TestContext.Current.CancellationToken;
        using var foreignLeaf = TestCertificates.CreateSelfSigned("CN=reenroll-foreign.example.com");

        // Empty statuses: chain building should fail before the revocation lookup even matters.
        var fakeService = new FakeRevocationStatusService(new Dictionary<string, OcspCertificateStatus>());

        var result = await EstEndpointMappings.VerifyReenrollCertificateAsync(foreignLeaf, _caCertificate, fakeService, ct);

        Assert.False(result);
    }

    [Fact]
    public void NormalizeSerial_agrees_with_X509Certificate2_SerialNumber_for_a_freshly_issued_certificate()
    {
        var issued = IssueLeaf("reenroll-serial-format.example.com");
        using var leaf = X509Certificate2.CreateFromPem(issued.CertificatePem);

        // GeneratedCertificate.SerialNumber is exactly what MarkAsIssuedAsync persists
        // (BigInteger.ToString(16).ToUpperInvariant()) — the format the dictionary lookup in
        // VerifyReenrollCertificateAsync must match.
        var normalized = EstEndpointMappings.NormalizeSerial(leaf.SerialNumber);

        Assert.Equal(issued.SerialNumber, normalized);
    }
}
