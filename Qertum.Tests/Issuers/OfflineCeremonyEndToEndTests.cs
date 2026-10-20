using System.Net.Http.Json;
using Qertum.Cli.Root;
using Qertum.Services;
using Qertum.Services.Crypto;
using Qertum.Services.Issuers;
using CertificateRequest = Qertum.Services.CertificateRequest;

namespace Qertum.Tests.Issuers;

public sealed class OfflineCeremonyEndToEndTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Theory]
    [InlineData(CertificateKeyAlgorithm.Rsa)]
    [InlineData(CertificateKeyAlgorithm.EcdsaP256)]
    [InlineData(CertificateKeyAlgorithm.MlDsa65)]
    public async Task InitSignInstallIssue_LeafChainsToTheOfflineRoot(CertificateKeyAlgorithm rootAlgorithm)
    {
        await using var host = new IssuerApiHost();
        var rootDir = Directory.CreateTempSubdirectory("e2e-root-").FullName;
        try
        {
            var root = new OfflineRoot(Path.Combine(rootDir, "r"), TimeProvider.System);
            root.Init(CaCertificateBuilder.SubjectName("E2E Root", null, null, null, null, null), rootAlgorithm, 7300, "pw");

            var created = await (await host.Admin().PostAsJsonAsync("/v1/issuers/intermediates", new CreateIntermediateRequest
            {
                Name = "E2E Issuing", CommonName = "E2E Issuing", KeyAlgorithm = rootAlgorithm == CertificateKeyAlgorithm.MlDsa65
                    ? CertificateKeyAlgorithm.MlDsa65 : CertificateKeyAlgorithm.EcdsaP256,
                ValidityDays = 1825, PathLength = 0, PermittedDnsSuffixes = ["corp.example"]
            }, Ct)).Content.ReadFromJsonAsync<CreateIntermediateResponse>(Ct);
            var (certificatePath, chainPath) = root.Sign(created!.RequestFile!, "pw");
            (await host.Admin().PostAsJsonAsync($"/v1/issuers/{created.Issuer.Id}/certificate",
                new InstallIssuerCertificateRequest(File.ReadAllText(certificatePath), File.ReadAllText(chainPath)), Ct))
                .EnsureSuccessStatusCode();

            var handle = await host.Registry.GetDefaultAsync(Ct);
            var leaf = handle!.Generator!.GenerateCertificate(new CertificateRequest { CommonName = "www.corp.example", Type = "WebServer" }, new CaSettings { PqcStage = PqcStage.Off });
            var chain = await host.Registry.ChainForAsync(handle.Issuer.Id, Ct);

            // Structural verification for every algorithm (BouncyCastle through the codec).
            var leafCert = QertumKeyCodec.ReadCertificatePem(leaf.CertificatePem)!;
            var path = ChainVerifier.Build(leafCert, [.. chain.Select(p => QertumKeyCodec.ReadCertificatePem(p)!)]);
            Assert.NotNull(path.Path);
            Assert.Equal(3, path.Path!.Count);

            // .NET X509Chain for the classical roots (it cannot verify ML-DSA on every platform).
            if (rootAlgorithm != CertificateKeyAlgorithm.MlDsa65)
            {
                using var x509Chain = new System.Security.Cryptography.X509Certificates.X509Chain();
                x509Chain.ChainPolicy.TrustMode = System.Security.Cryptography.X509Certificates.X509ChainTrustMode.CustomRootTrust;
                x509Chain.ChainPolicy.RevocationMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck;
                x509Chain.ChainPolicy.CustomTrustStore.Add(System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPem(chain[^1]));
                x509Chain.ChainPolicy.ExtraStore.Add(System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPem(chain[0]));
                Assert.True(x509Chain.Build(System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPem(leaf.CertificatePem)),
                    string.Join("; ", x509Chain.ChainStatus.Select(s => s.StatusInformation)));

                var openSsl = Qertum.Tests.Crypto.OpenSslTool.Find();
                if (openSsl is not null)
                {
                    File.WriteAllText(Path.Combine(rootDir, "root.pem"), chain[^1]);
                    File.WriteAllText(Path.Combine(rootDir, "mid.pem"), chain[0]);
                    File.WriteAllText(Path.Combine(rootDir, "leaf.pem"), leaf.CertificatePem);
                    var (exit, output) = Qertum.Tests.Crypto.OpenSslTool.Run(openSsl,
                        $"verify -CAfile {Path.Combine(rootDir, "root.pem")} -untrusted {Path.Combine(rootDir, "mid.pem")} {Path.Combine(rootDir, "leaf.pem")}");
                    Assert.True(exit == 0, output);
                }
            }

            // Root CRL round trip: sign offline, upload, served verbatim.
            var crlPath = root.Crl([], 365, "pw");
            var rootId = (await host.Admin().GetFromJsonAsync<List<IssuerResponse>>("/v1/issuers", Ct))!.Single(i => i.Kind == IssuerKind.Root).Id;
            (await host.Admin().PostAsync($"/v1/issuers/{rootId}/crl", new ByteArrayContent(File.ReadAllBytes(crlPath)), Ct)).EnsureSuccessStatusCode();
            Assert.Equal(File.ReadAllBytes(crlPath), await host.Anonymous().GetByteArrayAsync($"/crl/{rootId}", Ct));
        }
        finally { Directory.Delete(rootDir, true); }
    }
}
