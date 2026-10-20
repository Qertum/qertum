using System.Net;
using Qertum.Cli.Doctor;
using Qertum.Cli.Doctor.Checks;

namespace Qertum.Tests.Cli.Doctor;

public sealed class TrustCheckTests
{
    private const string Bundle = "https://ca.test/v1/issuers/trust-bundle?format=pem";
    private static readonly DateTime Now = DoctorTestSupport.Now.UtcDateTime;

    private static Task<DoctorResult> Run(FakeHttp http, out DoctorContext context, RootStoreAnswer store = RootStoreAnswer.Installed,
        bool apiReachable = true, Action<DoctorContext>? arrange = null)
    {
        context = DoctorTestSupport.Context(http, roots: new FakeRootStore(store));
        context.Shared.ApiReachable = apiReachable;
        arrange?.Invoke(context);
        return new TrustCheck().RunAsync(context, TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task AValidRootInstalledOnThisMachine_Passes_AndIsShared()
    {
        var root = DoctorPki.Root("Example Root", Now.AddYears(-1), Now.AddYears(9));
        var http = new FakeHttp().Route(Bundle, HttpStatusCode.OK, DoctorPki.Pem(root.Certificate), "application/x-pem-file");

        var result = await Run(http, out var context);

        Assert.Equal(DoctorStatus.Pass, result.Status);
        Assert.Single(context.Shared.Roots);
        Assert.Contains(result.Verified, v => v.Contains("self-signature", StringComparison.Ordinal));
        Assert.Contains(result.Verified, v => v.Contains("installed", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(result.NotVerified, v => v.Contains("browser", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task ARootNotInTheStore_Warns_WithTheFingerprintAndAnInstallHint()
    {
        var root = DoctorPki.Root("Example Root", Now.AddYears(-1), Now.AddYears(9));
        var http = new FakeHttp().Route(Bundle, HttpStatusCode.OK, DoctorPki.Pem(root.Certificate));

        var result = await Run(http, out _, RootStoreAnswer.NotInstalled);

        Assert.Equal(DoctorStatus.Warn, result.Status);
        Assert.Contains(result.Findings, f => f.Contains("Example Root", StringComparison.Ordinal) && f.Contains("not installed", StringComparison.Ordinal));
        Assert.Contains("qca issuers trust-bundle", result.Hint, StringComparison.Ordinal);
    }

    [Fact]
    public async Task WhenThePlatformCannotTell_ItSaysSo_AndDoesNotWarn()
    {
        var root = DoctorPki.Root("Example Root", Now.AddYears(-1), Now.AddYears(9));
        var http = new FakeHttp().Route(Bundle, HttpStatusCode.OK, DoctorPki.Pem(root.Certificate));

        var result = await Run(http, out _, RootStoreAnswer.CannotTell);

        Assert.Equal(DoctorStatus.Pass, result.Status);
        Assert.Contains(result.NotVerified, v => v.Contains("cannot tell", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task AnExpiredRoot_Fails()
    {
        var root = DoctorPki.Root("Old Root", Now.AddYears(-10), Now.AddDays(-1));
        var http = new FakeHttp().Route(Bundle, HttpStatusCode.OK, DoctorPki.Pem(root.Certificate));

        var result = await Run(http, out _);

        Assert.Equal(DoctorStatus.Fail, result.Status);
        Assert.Contains(result.Findings, f => f.Contains("Old Root", StringComparison.Ordinal) && f.Contains("expired", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ACertificateThatIsNotSelfSigned_InTheBundle_Fails()
    {
        var root = DoctorPki.Root("Example Root", Now.AddYears(-1), Now.AddYears(9));
        var issuing = root.Intermediate("Issuing", Now.AddYears(-1), Now.AddYears(4));
        var http = new FakeHttp().Route(Bundle, HttpStatusCode.OK, DoctorPki.Pem(issuing.Certificate));

        var result = await Run(http, out _);

        Assert.Equal(DoctorStatus.Fail, result.Status);
        Assert.Contains(result.Findings, f => f.Contains("not self-signed", StringComparison.Ordinal));
    }

    [Fact]
    public async Task GarbageWhereAPemBundleShouldBe_Fails_NotACrash()
    {
        var http = new FakeHttp().Route(Bundle, HttpStatusCode.OK, "<html>login</html>");

        var result = await Run(http, out _);

        Assert.Equal(DoctorStatus.Fail, result.Status);
        Assert.Contains("no certificate", result.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A503_MeansNoTrustAnchorYet()
    {
        var result = await Run(new FakeHttp().Route(Bundle, HttpStatusCode.ServiceUnavailable), out _);

        Assert.Equal(DoctorStatus.Fail, result.Status);
        Assert.Contains("no trust anchor", result.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheBundleRequest_NeverCarriesTheToken()
    {
        var root = DoctorPki.Root("Example Root", Now.AddYears(-1), Now.AddYears(9));
        var http = new FakeHttp().Route(Bundle, HttpStatusCode.OK, DoctorPki.Pem(root.Certificate));

        await Run(http, out _);

        Assert.All(http.Seen, s => Assert.Null(s.Authorization));
    }

    [Fact]
    public async Task WithTheIssuerList_EachChainIsVerifiedToABundleRoot_AndSharedForTheCrlCheck()
    {
        var root = DoctorPki.Root("Example Root", Now.AddYears(-1), Now.AddYears(9));
        var issuing = root.Intermediate("Issuing CA", Now.AddYears(-1), Now.AddYears(4));
        var id = Guid.NewGuid();
        var http = new FakeHttp()
            .Route(Bundle, HttpStatusCode.OK, DoctorPki.Pem(root.Certificate))
            .Route($"https://ca.test/v1/issuers/{id}/chain?format=pem", HttpStatusCode.OK, DoctorPki.Pem(issuing.Certificate, root.Certificate));

        var result = await Run(http, out var context, arrange: c => c.Shared.Issuers = [Issuer(id, "Issuing CA")]);

        Assert.Equal(DoctorStatus.Pass, result.Status);
        Assert.Contains(result.Verified, v => v.Contains("1 issuer chain", StringComparison.Ordinal));
        Assert.Contains(context.Shared.IssuerCertificates, c => c.SubjectDN.ToString()!.Contains("Issuing CA", StringComparison.Ordinal));
        Assert.All(http.Seen, s => Assert.Null(s.Authorization));
    }

    [Fact]
    public async Task AChainWhoseRootIsNotInTheBundle_Fails_NamingTheIssuer()
    {
        var root = DoctorPki.Root("Example Root", Now.AddYears(-1), Now.AddYears(9));
        var other = DoctorPki.Root("Other Root", Now.AddYears(-1), Now.AddYears(9));
        var issuing = other.Intermediate("Rogue CA", Now.AddYears(-1), Now.AddYears(4));
        var id = Guid.NewGuid();
        var http = new FakeHttp()
            .Route(Bundle, HttpStatusCode.OK, DoctorPki.Pem(root.Certificate))
            .Route($"https://ca.test/v1/issuers/{id}/chain?format=pem", HttpStatusCode.OK, DoctorPki.Pem(issuing.Certificate, other.Certificate));

        var result = await Run(http, out _, arrange: c => c.Shared.Issuers = [Issuer(id, "Rogue CA")]);

        Assert.Equal(DoctorStatus.Fail, result.Status);
        Assert.Contains(result.Findings, f => f.Contains("Rogue CA", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AChainWithABrokenSignature_Fails()
    {
        var root = DoctorPki.Root("Example Root", Now.AddYears(-1), Now.AddYears(9));
        var impostorKey = DoctorPki.NewKey();
        var forged = DoctorPki.Issue("Forged CA", DoctorPki.NewKey(), "Example Root", impostorKey, Now.AddYears(-1), Now.AddYears(4));
        var id = Guid.NewGuid();
        var http = new FakeHttp()
            .Route(Bundle, HttpStatusCode.OK, DoctorPki.Pem(root.Certificate))
            .Route($"https://ca.test/v1/issuers/{id}/chain?format=pem", HttpStatusCode.OK, DoctorPki.Pem(forged, root.Certificate));

        var result = await Run(http, out _, arrange: c => c.Shared.Issuers = [Issuer(id, "Forged CA")]);

        Assert.Equal(DoctorStatus.Fail, result.Status);
    }

    [Fact]
    public async Task WithoutTheIssuerList_ChainsAreNotVerified_AndSaidSo()
    {
        var root = DoctorPki.Root("Example Root", Now.AddYears(-1), Now.AddYears(9));
        var http = new FakeHttp().Route(Bundle, HttpStatusCode.OK, DoctorPki.Pem(root.Certificate));

        var result = await Run(http, out _);

        Assert.Contains(result.NotVerified, v => v.Contains("issuer chains", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AnUnreachableApi_IsSkipped()
    {
        var result = await Run(new FakeHttp(), out _, apiReachable: false);

        Assert.Equal(DoctorStatus.Skipped, result.Status);
    }

    private static Qertum.Services.IssuerResponse Issuer(Guid id, string name) => new(
        new Qertum.Services.IssuerId(id), name, Qertum.Services.IssuerKind.Intermediate, null, Qertum.Services.IssuerKeyCustody.Online,
        Qertum.Services.IssuerStatus.Active, false, $"CN={name}", "01", "ECDSA-P256", null, null, null, [], [], [], [], null, null,
        DateTime.UtcNow, null, null, null, null);

    [Fact]
    public async Task ARootThatFailed_IsNeverCountedAsVerified()
    {
        var expired = DoctorPki.Root("Old Root", Now.AddYears(-10), Now.AddDays(-1));
        var http = new FakeHttp().Route(Bundle, HttpStatusCode.OK, DoctorPki.Pem(expired.Certificate));

        var result = await Run(http, out _);

        Assert.Equal(DoctorStatus.Fail, result.Status);
        Assert.DoesNotContain(result.Verified, v => v.Contains("self-signature", StringComparison.Ordinal));
    }

    [Fact]
    public async Task InAMixedBundle_OnlyTheRootsThatPassedAreCounted()
    {
        var good = DoctorPki.Root("Good Root", Now.AddYears(-1), Now.AddYears(9));
        var expired = DoctorPki.Root("Old Root", Now.AddYears(-10), Now.AddDays(-1));
        var http = new FakeHttp().Route(Bundle, HttpStatusCode.OK, DoctorPki.Pem(good.Certificate, expired.Certificate));

        var result = await Run(http, out _);

        Assert.Equal(DoctorStatus.Fail, result.Status);
        Assert.Contains(result.Verified, v => v.StartsWith("1 root(s): self-signature", StringComparison.Ordinal));
    }
}
