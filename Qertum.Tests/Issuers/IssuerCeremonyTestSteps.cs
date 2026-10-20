using System.Net;
using System.Net.Http.Json;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Qertum.Services;
using Qertum.Services.Crypto;
using Qertum.Services.Issuers;

namespace Qertum.Tests.Issuers;

/// <summary>The steps of an offline ceremony, shared by the install and CRL-upload tests.</summary>
internal static class IssuerCeremonyTestSteps
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static readonly DateTime Now = DateTime.UtcNow;

    internal static async Task<CreateIntermediateResponse> PendingAsync(IssuerApiHost host, int? pathLength = 0,
        List<string>? permitted = null, List<string>? excluded = null)
    {
        var response = await host.Admin().PostAsJsonAsync("/v1/issuers/intermediates", new CreateIntermediateRequest
        {
            Name = "Issuing CA", CommonName = "Issuing CA", KeyAlgorithm = CertificateKeyAlgorithm.EcdsaP256,
            ValidityDays = 365, PathLength = pathLength,
            PermittedDnsSuffixes = permitted ?? ["corp.example"], ExcludedDnsSuffixes = excluded ?? []
        }, Ct);
        return (await response.Content.ReadFromJsonAsync<CreateIntermediateResponse>(Ct))!;
    }

    internal static X509Certificate Sign((AsymmetricCipherKeyPair Key, X509Certificate Cert) root, IntermediateRequestFile file,
        SubordinateCaProfile? profile = null, DateTime? notAfter = null, AsymmetricKeyParameter? overrideKey = null)
    {
        var csr = QertumKeyCodec.ReadCertificationRequestPem(file.CsrPem);
        var spki = overrideKey is null ? csr.GetCertificationRequestInfo().SubjectPublicKeyInfo : QertumKeyCodec.ToSubjectPublicKeyInfo(overrideKey);
        return CaCertificateBuilder.IssueSubordinate(new LocalKeyPairCaSigner(root.Key), root.Cert, spki,
            csr.GetCertificationRequestInfo().Subject,
            profile ?? new SubordinateCaProfile(file.PathLength, file.PermittedDnsSuffixes, file.ExcludedDnsSuffixes, file.PermittedIpRanges, file.ExcludedIpRanges),
            Now.AddMinutes(-5), notAfter ?? Now.AddDays(365));
    }

    internal static Task<HttpResponseMessage> InstallAsync(IssuerApiHost host, IssuerId id, X509Certificate cert, params X509Certificate[] chain) =>
        host.Admin().PostAsJsonAsync($"/v1/issuers/{id}/certificate", new InstallIssuerCertificateRequest(
            QertumKeyCodec.WriteCertificatePem(cert), string.Concat(chain.Select(QertumKeyCodec.WriteCertificatePem))), Ct);

}
