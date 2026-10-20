using System.Text.Json;
using Org.BouncyCastle.X509;
using Qertum.Cli.Commands;
using Qertum.Cli.Root;
using Qertum.Services;
using Qertum.Services.Crypto;
using Qertum.Services.Issuers;
using Qertum.Tests.Issuers;

namespace Qertum.Tests.Cli;

public sealed class OfflineRootTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("offline-root-").FullName;

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch { /* best effort */ }
    }

    private OfflineRoot Root() => new(_dir, TimeProvider.System);

    private OfflineRoot InitializedRoot(CertificateKeyAlgorithm algorithm = CertificateKeyAlgorithm.EcdsaP384)
    {
        var root = Root();
        root.Init(CaCertificateBuilder.SubjectName("Offline Root", "Qertum", null, "FI", null, null), algorithm, 7300, "root-pass");
        return root;
    }

    private static IntermediateRequestFile RequestFile(int validityDays = 1825)
    {
        var key = AlgorithmStrategyFactory.CreateIssuer(CertificateKeyAlgorithm.EcdsaP256).GenerateCaKeyPair(new Org.BouncyCastle.Security.SecureRandom());
        var profile = new SubordinateCaProfile(0, ["corp.example"], [], [], []);
        var csr = CaCertificateBuilder.BuildRequest(key, CaCertificateBuilder.SubjectName("Issuing CA", null, null, null, null, null), profile);
        return new IntermediateRequestFile(IntermediateRequestFile.CurrentFormat, new IssuerId(Guid.NewGuid()), "Issuing CA",
            QertumKeyCodec.WriteCertificationRequestPem(csr), validityDays, 0, ["corp.example"], [], [], []);
    }

    [Fact]
    public void Init_WritesAnEncryptedKey_ACertificate_AndState()
    {
        InitializedRoot();

        var keyPem = File.ReadAllText(Path.Combine(_dir, OfflineRoot.KeyFile));
        Assert.StartsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----", keyPem);
        var facts = IssuerCertificateFacts.Read(File.ReadAllText(Path.Combine(_dir, OfflineRoot.CertificateFile)));
        Assert.True(facts.IsSelfSigned);
        Assert.Equal(CertificateKeyAlgorithm.EcdsaP384, facts.KeyAlgorithm);
        Assert.True(File.Exists(Path.Combine(_dir, OfflineRoot.StateFile)));
    }

    [Fact]
    public void Init_RefusesANonEmptyDirectory()
    {
        File.WriteAllText(Path.Combine(_dir, "something"), "x");

        Assert.Throws<InvalidOperationException>(() =>
            Root().Init(CaCertificateBuilder.SubjectName("R", null, null, null, null, null), CertificateKeyAlgorithm.Rsa, 365, "p"));
    }

    [Fact]
    public void Sign_ProducesAConstrainedCaUnderTheRoot_AndRecordsItsSerial()
    {
        var root = InitializedRoot();

        var (certificatePath, chainPath) = root.Sign(RequestFile(), "root-pass");

        var cert = QertumKeyCodec.ReadCertificatePem(File.ReadAllText(certificatePath))!;
        var rootCert = QertumKeyCodec.ReadCertificatePem(File.ReadAllText(chainPath))!;
        Assert.True(cert.IsSignatureValid(QertumKeyCodec.VerifierFor(QertumKeyCodec.PublicKeyOf(rootCert))));
        var facts = IssuerCertificateFacts.Read(cert);
        Assert.Equal(0, facts.PathLengthConstraint);
        Assert.Equal(["corp.example"], facts.PermittedDnsSuffixes);
        var state = JsonSerializer.Deserialize<OfflineRootState>(File.ReadAllText(Path.Combine(_dir, OfflineRoot.StateFile)))!;
        Assert.Equal(facts.SerialNumber, Assert.Single(state.Issued).SerialHex);
    }

    [Fact]
    public void Sign_RefusesValidityBeyondTheRoot_AndAWrongPassphrase()
    {
        var root = InitializedRoot();

        Assert.Throws<InvalidOperationException>(() => root.Sign(RequestFile(validityDays: 9000), "root-pass"));
        Assert.Throws<ArgumentException>(() => root.Sign(RequestFile(), "wrong"));
    }

    [Fact]
    public void Sign_RefusesARequestFileWhoseCsrDoesNotVerify()
    {
        var root = InitializedRoot();
        var file = RequestFile();
        var other = RequestFile();
        // CSR of one request, constraints of another: still fine; but a tampered CSR must fail.
        var tampered = file with { CsrPem = file.CsrPem.Replace("A", "B", StringComparison.Ordinal) };

        Assert.ThrowsAny<Exception>(() => root.Sign(tampered, "root-pass"));
        _ = other;
    }

    [Fact]
    public void Crl_IncrementsTheNumber_AndKeepsEveryRevocation()
    {
        var root = InitializedRoot();
        var (certificatePath, _) = root.Sign(RequestFile(), "root-pass");
        var serial = IssuerCertificateFacts.Read(File.ReadAllText(certificatePath)).SerialNumber;

        root.Crl([(serial, "keyCompromise")], 365, "root-pass");
        var second = root.Crl([], 365, "root-pass");

        var crl = new X509CrlParser().ReadCrl(File.ReadAllBytes(second));
        Assert.NotNull(crl.GetRevokedCertificate(new Org.BouncyCastle.Math.BigInteger(serial, 16)));
        var state = JsonSerializer.Deserialize<OfflineRootState>(File.ReadAllText(Path.Combine(_dir, OfflineRoot.StateFile)))!;
        Assert.Equal(2, state.CrlNumber);
    }

    [Fact]
    public void RootCommand_HasInitSignCrl_AndNoPassphraseOption()
    {
        var command = RootCommands.Build(new FixedPrompt("x"));

        Assert.Equal(["crl", "init", "sign"], command.Subcommands.Select(c => c.Name).Order(StringComparer.Ordinal));
        Assert.DoesNotContain(command.Subcommands.SelectMany(c => c.Options), o => o.Name.Contains("pass", StringComparison.OrdinalIgnoreCase));
        Assert.Empty(command.Parse("init --dir /tmp/x --cn Root --algorithm ECDSA-P384").Errors);
    }

    private sealed class FixedPrompt(string value) : IPassphrasePrompt
    {
        public string Read(string prompt) => value;
    }
}
