using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using Org.BouncyCastle.X509;
using Qertum.Cli.Root;
using Qertum.Services;
using Qertum.Services.Crypto;
using Qertum.Services.Issuers;
using CertificateRequest = Qertum.Services.CertificateRequest;

namespace Qertum.Tests.Issuers;

/// <summary>
/// The rehearsal behind the Issuer Compromise Recovery page of the public wiki, case A: the online issuing intermediate's key is
/// compromised while the offline root is intact. It plays the Qertum-side recovery steps against the real API and the real
/// offline root tool, asserts what a relying party and an operator would observe, and prints the machine time of each step
/// (the runbook quotes these as the measured part of the recovery time). It cannot run bulk renew or bulk revoke: the host has
/// no queue consumer, so those steps are seeded rows here and stated as untested in the runbook.
/// </summary>
public sealed class IssuerCompromiseRehearsalTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static async Task<IssuerResponse> CreateAndInstallAsync(IssuerApiHost host, OfflineRoot root, string name)
    {
        var created = await (await host.Admin().PostAsJsonAsync("/v1/issuers/intermediates", new CreateIntermediateRequest
        {
            Name = name, CommonName = name, KeyAlgorithm = CertificateKeyAlgorithm.EcdsaP256,
            ValidityDays = 1825, PathLength = 0, PermittedDnsSuffixes = ["corp.example"]
        }, Ct)).Content.ReadFromJsonAsync<CreateIntermediateResponse>(Ct);

        var (certificatePath, chainPath) = root.Sign(created!.RequestFile!, "pw");
        var installed = await host.Admin().PostAsJsonAsync($"/v1/issuers/{created.Issuer.Id}/certificate",
            new InstallIssuerCertificateRequest(File.ReadAllText(certificatePath), File.ReadAllText(chainPath)), Ct);
        installed.EnsureSuccessStatusCode();
        return (await installed.Content.ReadFromJsonAsync<IssuerResponse>(Ct))!;
    }

    private static async Task<IssuerResponse> GetAsync(IssuerApiHost host, IssuerId id) =>
        (await host.Admin().GetFromJsonAsync<IssuerResponse>($"/v1/issuers/{id}", Ct))!;

    [Fact]
    public async Task OnlineIntermediateCompromise_IsRecoverable_WithoutTouchingTheRoot_AndTheStepsAreTimed()
    {
        await using var host = new IssuerApiHost();
        var rootDir = Directory.CreateTempSubdirectory("rehearsal-root-").FullName;
        var timings = new List<(string Step, TimeSpan Elapsed)>();
        try
        {
            // --- Before the incident: an offline root, an online issuing intermediate, two certificates issued under it.
            var root = new OfflineRoot(Path.Combine(rootDir, "r"), TimeProvider.System);
            root.Init(CaCertificateBuilder.SubjectName("Rehearsal Root", null, null, null, null, null), CertificateKeyAlgorithm.EcdsaP384, 7300, "pw");
            var compromised = await CreateAndInstallAsync(host, root, "Compromised Issuing CA");
            var rootIssuer = (await host.Admin().GetFromJsonAsync<List<IssuerResponse>>("/v1/issuers", Ct))!.Single(i => i.Kind == IssuerKind.Root);
            Assert.True((await GetAsync(host, compromised.Id)).IsDefault);

            var oldGenerator = (await host.Registry.GetAsync(compromised.Id, Ct))!.Generator!;
            await host.SeedIssuedAsync(compromised.Id, oldGenerator, revoked: false, Ct, "web1.corp.example");
            await host.SeedIssuedAsync(compromised.Id, oldGenerator, revoked: false, Ct, "web2.corp.example");

            // --- The incident: step by step, as the runbook lists them. ---
            var clock = Stopwatch.StartNew();
            void Mark(string step) { timings.Add((step, clock.Elapsed)); clock.Restart(); }

            // 1. Replacement intermediate: create, sign on the offline root, install.
            var replacement = await CreateAndInstallAsync(host, root, "Replacement Issuing CA");
            Assert.Equal(IssuerStatus.Active, replacement.Status);
            Mark("1 create, sign offline and install the replacement intermediate");

            // 2. Make the replacement the default so new issuance moves off the compromised key.
            (await host.Admin().PostAsync($"/v1/issuers/{replacement.Id}/make-default", null, Ct)).EnsureSuccessStatusCode();
            Assert.Equal(replacement.Id, await host.DefaultIssuerIdAsync(Ct));
            Mark("2 make the replacement default");

            // 3. The offline root revokes the compromised intermediate on a CRL, and the CRL is uploaded.
            var crlPath = root.Crl([(compromised.SerialNumber!, "keyCompromise")], 30, "pw");
            Mark("3a sign the root CRL offline");
            (await host.Admin().PostAsync($"/v1/issuers/{rootIssuer.Id}/crl", new ByteArrayContent(File.ReadAllBytes(crlPath)), Ct)).EnsureSuccessStatusCode();
            Mark("3b upload the root CRL");

            // --- What an operator and a relying party now see. ---
            var oldNow = await GetAsync(host, compromised.Id);
            Assert.Equal(IssuerStatus.Retired, oldNow.Status);
            Assert.False(oldNow.IsDefault);
            Assert.True((await GetAsync(host, replacement.Id)).IsDefault);

            // The root's CRL, served to relying parties, lists the compromised intermediate and not the replacement.
            var rootCrl = new X509CrlParser().ReadCrl(await host.Anonymous().GetByteArrayAsync($"/crl/{rootIssuer.Id}", Ct));
            var listed = rootCrl.GetRevokedCertificates()!.Select(e => e.SerialNumber.ToString(16).ToUpperInvariant()).ToList();
            Assert.Contains(compromised.SerialNumber!.TrimStart('0').ToUpperInvariant(), listed);
            Assert.DoesNotContain(replacement.SerialNumber!.TrimStart('0').ToUpperInvariant(), listed);

            // The retired issuer still answers CRL requests (its leaves must stay checkable) but can no longer be the default.
            Assert.Equal(HttpStatusCode.OK, (await host.Anonymous().GetAsync($"/crl/{compromised.Id}", Ct)).StatusCode);

            // A certificate issued now chains to the same, unchanged root through the replacement.
            var newHandle = (await host.Registry.GetDefaultAsync(Ct))!;
            Assert.Equal(replacement.Id, newHandle.Issuer.Id);
            var fresh = newHandle.Generator!.GenerateCertificate(new CertificateRequest { CommonName = "web1.corp.example", Type = "WebServer" }, new CaSettings { PqcStage = PqcStage.Off });
            var chain = await host.Registry.ChainForAsync(newHandle.Issuer.Id, Ct);
            var path = ChainVerifier.Build(QertumKeyCodec.ReadCertificatePem(fresh.CertificatePem)!, [.. chain.Select(p => QertumKeyCodec.ReadCertificatePem(p)!)]);
            Assert.NotNull(path.Path);
            Assert.Equal("CN=Rehearsal Root", QertumKeyCodec.ReadCertificatePem(chain[^1])!.SubjectDN.ToString());
            Mark("4 verify");

            // The trust anchors did not change: the bundle still holds the one root, nothing to redistribute for case A.
            var bundle = await host.Anonymous().GetStringAsync("/v1/issuers/trust-bundle", Ct);
            Assert.Equal(1, bundle.Split("-----BEGIN CERTIFICATE-----").Length - 1);

            // The compromised key stays on this host until its last certificate expires: archive is refused (the runbook says so).
            var archive = await host.Admin().PostAsync($"/v1/issuers/{compromised.Id}/archive", null, Ct);
            Assert.Equal(HttpStatusCode.Conflict, archive.StatusCode);
            Assert.Contains("unexpired", await archive.Content.ReadAsStringAsync(Ct));
            Assert.True(host.Kit.Storage.HasKeyFile(await StoredIssuerAsync(host, compromised.Id)));

            // A pending-only delete does not remove an issued issuer either: there is no way to destroy it early (a recorded gap).
            Assert.Equal(HttpStatusCode.Conflict, (await host.Admin().DeleteAsync($"/v1/issuers/{compromised.Id}", Ct)).StatusCode);

            // A passing test shows no output: set REHEARSAL_TIMINGS_FILE to keep the per-step numbers the runbook quotes.
            var report = timings.Select(t => $"{t.Step}: {t.Elapsed.TotalMilliseconds:F0} ms").ToList();
            TestContext.Current.TestOutputHelper?.WriteLine(string.Join(Environment.NewLine, report));
            if (Environment.GetEnvironmentVariable("REHEARSAL_TIMINGS_FILE") is { Length: > 0 } file)
                File.WriteAllLines(file, report);
        }
        finally
        {
            Directory.Delete(rootDir, true);
        }
    }

    [Fact]
    public async Task OfflineRootCompromise_ReplacesTheChain_ButTheCompromisedRootStaysInTheTrustBundle()
    {
        // Case B. Qertum cannot revoke a root (nothing is above it): relying parties must drop it from their trust stores.
        // The test records what Qertum itself still hands out afterwards, because the runbook must not promise more.
        await using var host = new IssuerApiHost();
        var rootDir = Directory.CreateTempSubdirectory("rehearsal-root-b-").FullName;
        try
        {
            var oldRoot = new OfflineRoot(Path.Combine(rootDir, "old"), TimeProvider.System);
            oldRoot.Init(CaCertificateBuilder.SubjectName("Old Root", null, null, null, null, null), CertificateKeyAlgorithm.EcdsaP384, 7300, "pw");
            var oldIssuing = await CreateAndInstallAsync(host, oldRoot, "Old Issuing CA");

            var newRoot = new OfflineRoot(Path.Combine(rootDir, "new"), TimeProvider.System);
            newRoot.Init(CaCertificateBuilder.SubjectName("New Root", null, null, null, null, null), CertificateKeyAlgorithm.EcdsaP384, 7300, "pw");
            var newIssuing = await CreateAndInstallAsync(host, newRoot, "New Issuing CA");
            (await host.Admin().PostAsync($"/v1/issuers/{newIssuing.Id}/make-default", null, Ct)).EnsureSuccessStatusCode();
            (await host.Admin().PostAsync($"/v1/issuers/{oldIssuing.Id}/retire", null, Ct)).EnsureSuccessStatusCode();

            // New issuance chains to the new root.
            var handle = (await host.Registry.GetDefaultAsync(Ct))!;
            var chain = await host.Registry.ChainForAsync(handle.Issuer.Id, Ct);
            Assert.Equal("CN=New Root", QertumKeyCodec.ReadCertificatePem(chain[^1])!.SubjectDN.ToString());

            // Both roots are still offered while the old issuing CA is Retired (only an Archived issuer drops out, and archive
            // waits for its last certificate to expire). Pins today's behaviour: if Qertum ever lets an operator withdraw a
            // compromised root from the bundle, update the Issuer Compromise Recovery wiki page.
            var bundle = await host.Anonymous().GetStringAsync("/v1/issuers/trust-bundle", Ct);
            Assert.Equal(2, bundle.Split("-----BEGIN CERTIFICATE-----").Length - 1);
        }
        finally
        {
            Directory.Delete(rootDir, true);
        }
    }

    private static async Task<Issuer> StoredIssuerAsync(IssuerApiHost host, IssuerId id)
    {
        await using var db = host.Kit.Database.CreateContext();
        return (await db.Issuers.FindAsync([id], Ct))!;
    }
}
