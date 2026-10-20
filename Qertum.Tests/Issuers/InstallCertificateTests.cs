using System.Net;
using System.Net.Http.Json;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Qertum.Services;
using Qertum.Services.Crypto;
using Qertum.Services.Issuers;

namespace Qertum.Tests.Issuers;

public sealed class InstallCertificateTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static readonly DateTime Now = DateTime.UtcNow;

    [Fact]
    public async Task ValidInstall_ActivatesTheIntermediate_RegistersTheOfflineRoot_AndBecomesDefault()
    {
        await using var host = new IssuerApiHost();
        var root = CaCertificateBuilderTests.Root();
        var pending = await IssuerCeremonyTestSteps.PendingAsync(host);

        var response = await IssuerCeremonyTestSteps.InstallAsync(host, pending.Issuer.Id, IssuerCeremonyTestSteps.Sign(root, pending.RequestFile!), root.Cert);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var all = await host.Admin().GetFromJsonAsync<List<IssuerResponse>>("/v1/issuers", Ct);
        var offlineRoot = Assert.Single(all!, i => i.Kind == IssuerKind.Root);
        Assert.Equal(IssuerKeyCustody.Offline, offlineRoot.KeyCustody);
        var intermediate = Assert.Single(all!, i => i.Id == pending.Issuer.Id);
        Assert.Equal(IssuerStatus.Active, intermediate.Status);
        Assert.True(intermediate.IsDefault);
        Assert.Equal(offlineRoot.Id, intermediate.ParentIssuerId);
        Assert.True((await host.Registry.GetDefaultAsync(Ct))!.CanIssue);
    }

    [Fact]
    public async Task Install_ChainInAnyOrder_IsAccepted()
    {
        await using var host = new IssuerApiHost();
        var root = CaCertificateBuilderTests.Root();
        var pending = await IssuerCeremonyTestSteps.PendingAsync(host);
        var cert = IssuerCeremonyTestSteps.Sign(root, pending.RequestFile!);

        // Leaf repeated, root twice: path building must not care.
        var response = await IssuerCeremonyTestSteps.InstallAsync(host, pending.Issuer.Id, cert, cert, root.Cert, root.Cert);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Install_ChainMissingTheRoot_IsRefused()
    {
        await using var host = new IssuerApiHost();
        var root = CaCertificateBuilderTests.Root();
        var pending = await IssuerCeremonyTestSteps.PendingAsync(host);

        var response = await IssuerCeremonyTestSteps.InstallAsync(host, pending.Issuer.Id, IssuerCeremonyTestSteps.Sign(root, pending.RequestFile!));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("self-signed root", await response.Content.ReadAsStringAsync(Ct));
    }

    [Fact]
    public async Task WrongKey_IsRefused()
    {
        await using var host = new IssuerApiHost();
        var root = CaCertificateBuilderTests.Root();
        var pending = await IssuerCeremonyTestSteps.PendingAsync(host);
        var otherKey = AlgorithmStrategyFactory.CreateIssuer(CertificateKeyAlgorithm.EcdsaP256).GenerateCaKeyPair(new SecureRandom()).Public;

        var response = await IssuerCeremonyTestSteps.InstallAsync(host, pending.Issuer.Id, IssuerCeremonyTestSteps.Sign(root, pending.RequestFile!, overrideKey: otherKey), root.Cert);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("pending key", await response.Content.ReadAsStringAsync(Ct));
    }

    [Fact]
    public async Task MissingPathLength_IsRefused()
    {
        await using var host = new IssuerApiHost();
        var root = CaCertificateBuilderTests.Root();
        var pending = await IssuerCeremonyTestSteps.PendingAsync(host, pathLength: 0);

        var response = await IssuerCeremonyTestSteps.InstallAsync(host, pending.Issuer.Id,
            IssuerCeremonyTestSteps.Sign(root, pending.RequestFile!, new SubordinateCaProfile(null, ["corp.example"], [], [], [])), root.Cert);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("path length", await response.Content.ReadAsStringAsync(Ct));
    }

    [Fact]
    public async Task DroppedOrWidenedNameConstraint_IsRefused()
    {
        await using var host = new IssuerApiHost();
        var root = CaCertificateBuilderTests.Root();
        var pending = await IssuerCeremonyTestSteps.PendingAsync(host, permitted: ["corp.example"], excluded: ["secret.corp.example"]);

        var dropped = await IssuerCeremonyTestSteps.InstallAsync(host, pending.Issuer.Id,
            IssuerCeremonyTestSteps.Sign(root, pending.RequestFile!, new SubordinateCaProfile(0, ["corp.example"], [], [], [])), root.Cert);
        var widened = await IssuerCeremonyTestSteps.InstallAsync(host, pending.Issuer.Id,
            IssuerCeremonyTestSteps.Sign(root, pending.RequestFile!, new SubordinateCaProfile(0, ["corp.example", "evil.example"], ["secret.corp.example"], [], [])), root.Cert);

        Assert.Equal(HttpStatusCode.BadRequest, dropped.StatusCode);
        Assert.Contains("secret.corp.example", await dropped.Content.ReadAsStringAsync(Ct));
        Assert.Equal(HttpStatusCode.BadRequest, widened.StatusCode);
        Assert.Contains("evil.example", await widened.Content.ReadAsStringAsync(Ct));
    }

    [Fact]
    public async Task NarrowerConstraints_AreAccepted()
    {
        await using var host = new IssuerApiHost();
        var root = CaCertificateBuilderTests.Root();
        var pending = await IssuerCeremonyTestSteps.PendingAsync(host, permitted: ["corp.example"]);

        var response = await IssuerCeremonyTestSteps.InstallAsync(host, pending.Issuer.Id,
            IssuerCeremonyTestSteps.Sign(root, pending.RequestFile!, new SubordinateCaProfile(0, ["eu.corp.example"], [], [], [])), root.Cert);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task NotACa_IsRefused()
    {
        await using var host = new IssuerApiHost();
        var root = CaCertificateBuilderTests.Root();
        var pending = await IssuerCeremonyTestSteps.PendingAsync(host);
        var csr = QertumKeyCodec.ReadCertificationRequestPem(pending.RequestFile!.CsrPem);
        var gen = new X509V3CertificateGenerator();
        gen.SetSerialNumber(Org.BouncyCastle.Math.BigInteger.ValueOf(7));
        gen.SetIssuerDN(root.Cert.SubjectDN);
        gen.SetSubjectDN(csr.GetCertificationRequestInfo().Subject);
        gen.SetNotBefore(Now.AddMinutes(-5));
        gen.SetNotAfter(Now.AddDays(30));
        gen.SetSubjectPublicKeyInfo(csr.GetCertificationRequestInfo().SubjectPublicKeyInfo);
        gen.AddExtension(Org.BouncyCastle.Asn1.X509.X509Extensions.BasicConstraints, true, new Org.BouncyCastle.Asn1.X509.BasicConstraints(false));
        var leafLike = gen.Generate(new LocalKeyPairCaSigner(root.Key).CreateSignatureFactory());

        var response = await IssuerCeremonyTestSteps.InstallAsync(host, pending.Issuer.Id, leafLike, root.Cert);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("cA", await response.Content.ReadAsStringAsync(Ct));
    }

    [Fact]
    public async Task ValidityBeyondTheParent_IsRefused()
    {
        await using var host = new IssuerApiHost();
        var root = CaCertificateBuilderTests.Root();
        var pending = await IssuerCeremonyTestSteps.PendingAsync(host);

        var response = await IssuerCeremonyTestSteps.InstallAsync(host, pending.Issuer.Id,
            IssuerCeremonyTestSteps.Sign(root, pending.RequestFile!, notAfter: root.Cert.NotAfter.AddDays(1)), root.Cert);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("outlive", await response.Content.ReadAsStringAsync(Ct));
    }

    [Fact]
    public async Task InstallingTwice_Is409()
    {
        await using var host = new IssuerApiHost();
        var root = CaCertificateBuilderTests.Root();
        var pending = await IssuerCeremonyTestSteps.PendingAsync(host);
        var cert = IssuerCeremonyTestSteps.Sign(root, pending.RequestFile!);
        await IssuerCeremonyTestSteps.InstallAsync(host, pending.Issuer.Id, cert, root.Cert);

        var again = await IssuerCeremonyTestSteps.InstallAsync(host, pending.Issuer.Id, cert, root.Cert);

        Assert.Equal(HttpStatusCode.Conflict, again.StatusCode);
    }
}
