using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Qertum.IdentityService.Services;
using Qertum.ServiceDefaults.Secrets;

namespace Qertum.Tests;

/// <summary>
/// Covers the identity provider's own key rotation. The behaviour these pin down used not to
/// exist: certificates were created once behind a <c>File.Exists</c> check and never revisited,
/// so expiry was an outage that could only be cleared by deleting the file — replacing the key
/// with no overlap and invalidating every token in flight.
/// </summary>
public sealed class IdentityCertificateStoreTests : IDisposable
{
    private static readonly TimeSpan Lifetime = TimeSpan.FromDays(1825);
    private static readonly TimeSpan RenewBefore = TimeSpan.FromDays(90);

    private readonly List<string> _tempDirectories = [];

    private string NewKeysDirectory()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"idp-keys-{Guid.NewGuid():N}");
        _tempDirectories.Add(dir);
        return dir;
    }

    private static IReadOnlyList<X509Certificate2> Ensure(string dir, DateTimeOffset now) =>
        IdentityCertificateStore.EnsureCertificates(
            dir, IdentityCertificateStore.SigningRole, "CN=Test Signing", Lifetime, RenewBefore, now,
            new LocalFileKeySecretProtector(dir));

    [Fact]
    public void CreatesACertificateOnFirstRun()
    {
        var dir = NewKeysDirectory();
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

        var certificates = Ensure(dir, now);

        var certificate = Assert.Single(certificates);
        Assert.True(certificate.HasPrivateKey);
        Assert.Equal("CN=Test Signing", certificate.Subject);

        // Backdated a day so clock skew cannot make a just-created certificate look
        // not-yet-valid to a relying party.
        Assert.True(certificate.NotBefore.ToUniversalTime() < now.UtcDateTime);
        Assert.Equal((now + Lifetime).UtcDateTime, certificate.NotAfter.ToUniversalTime(), TimeSpan.FromMinutes(1));
    }

    [Fact]
    public void ReusesTheExistingCertificateOnEveryRestartUntilRenewalIsDue()
    {
        var dir = NewKeysDirectory();
        var start = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

        var first = Ensure(dir, start).Single().Thumbprint;

        // Restarting must not mint a new key: doing so would invalidate every live token.
        Assert.Equal(first, Ensure(dir, start.AddMinutes(5)).Single().Thumbprint);
        Assert.Equal(first, Ensure(dir, start + Lifetime - RenewBefore - TimeSpan.FromDays(1)).Single().Thumbprint);
        Assert.Single(Directory.GetFiles(dir, "*.pfx"));
    }

    [Fact]
    public void RotatesInsideTheRenewalWindowAndKeepsTheOldCertificateRegistered()
    {
        var dir = NewKeysDirectory();
        var start = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

        var original = Ensure(dir, start).Single().Thumbprint;

        // One day into the renewal window a replacement appears — and the retiring certificate
        // stays registered, which is what keeps it in the JWKS document so tokens signed under
        // it still validate for the rest of the overlap.
        var afterRotation = Ensure(dir, start + Lifetime - RenewBefore + TimeSpan.FromDays(1));

        Assert.Equal(2, afterRotation.Count);
        Assert.Contains(afterRotation, c => c.Thumbprint == original);

        // Newest expiry first: OpenIddict signs with the first registered credential, so the
        // replacement must lead or rotation would publish a new key without ever using it.
        Assert.NotEqual(original, afterRotation[0].Thumbprint);
        Assert.True(afterRotation[0].NotAfter > afterRotation[1].NotAfter);
        Assert.Equal(2, Directory.GetFiles(dir, "*.pfx").Length);
    }

    [Fact]
    public void DropsCertificatesThatHaveFullyExpired()
    {
        var dir = NewKeysDirectory();
        var start = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

        var original = Ensure(dir, start).Single().Thumbprint;

        // Well past the original's expiry: it must not be registered any more (it would be
        // advertised in JWKS as a usable key) and a replacement must exist.
        var afterExpiry = Ensure(dir, start + Lifetime + TimeSpan.FromDays(1));

        var replacement = Assert.Single(afterExpiry);
        Assert.NotEqual(original, replacement.Thumbprint);
    }

    [Fact]
    public void AdoptsTheLegacyUnversionedFileWrittenByEarlierVersions()
    {
        var dir = NewKeysDirectory();
        Directory.CreateDirectory(dir);
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

        // Exactly what the old File.Exists-guarded bootstrap left behind: "signing.pfx".
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=Test Signing", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var legacy = request.CreateSelfSigned(now.AddDays(-1), now.AddYears(5));
        var legacyPath = Path.Combine(dir, "signing.pfx");
        File.WriteAllBytes(legacyPath, legacy.Export(X509ContentType.Pfx));

        var certificates = Ensure(dir, now);

        // An upgrade must not rotate the key and sign everyone out.
        var adopted = Assert.Single(certificates);
        Assert.Equal(legacy.Thumbprint, adopted.Thumbprint);
        Assert.True(File.Exists(legacyPath));
    }

    [Fact]
    public void WritesProtectedBytesNotRawPkcs12()
    {
        var dir = NewKeysDirectory();
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

        Ensure(dir, now);

        var pfxPath = Directory.EnumerateFiles(dir, "signing*.pfx").Single();
        var bytesOnDisk = File.ReadAllBytes(pfxPath);

        // A raw, unprotected PKCS12 file starts with a recognizable DER SEQUENCE header (0x30 0x82).
        // AES-GCM ciphertext essentially never does — this is the same shape of check the legacy
        // fallback below relies on, asserted from the other side.
        Assert.False(bytesOnDisk.Length > 2 && bytesOnDisk[0] == 0x30 && bytesOnDisk[1] == 0x82);
    }

    [Fact]
    public void StillAdoptsALegacyPfxThatWasNeverProtected()
    {
        var dir = NewKeysDirectory();
        Directory.CreateDirectory(dir);
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

        // A PFX written by literally today's code, before this task lands: raw, unprotected bytes.
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=Legacy", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var legacy = request.CreateSelfSigned(now.AddDays(-1), now.AddYears(5));
        File.WriteAllBytes(Path.Combine(dir, "signing-legacy.pfx"), legacy.Export(X509ContentType.Pfx));

        var loaded = Ensure(dir, now);

        Assert.Contains(loaded, c => c.Thumbprint == legacy.Thumbprint);
    }

    [Fact]
    public void ReplacesALegacyFileThatIsAlreadyInsideItsRenewalWindow()
    {
        var dir = NewKeysDirectory();
        Directory.CreateDirectory(dir);
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

        // A deployment that has been running long enough for the original 5-year certificate to
        // be nearly expired — the case that used to be an unrecoverable outage.
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=Test Signing", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var expiring = request.CreateSelfSigned(now.AddYears(-5), now.AddDays(10));
        File.WriteAllBytes(Path.Combine(dir, "signing.pfx"), expiring.Export(X509ContentType.Pfx));

        var certificates = Ensure(dir, now);

        Assert.Equal(2, certificates.Count);
        Assert.NotEqual(expiring.Thumbprint, certificates[0].Thumbprint);
        Assert.Contains(certificates, c => c.Thumbprint == expiring.Thumbprint);
    }

    [Fact]
    public void SkipsAnUnreadableFileRatherThanFailingToStart()
    {
        var dir = NewKeysDirectory();
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "signing-corrupt.pfx"), "not a pfx");

        var certificates = Ensure(dir, new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));

        // One corrupt file must not be a permanent outage; a working key is minted instead.
        var certificate = Assert.Single(certificates);
        Assert.True(certificate.HasPrivateKey);
    }

    [Fact]
    public void SigningAndEncryptionCertificatesDoNotShareFiles()
    {
        var dir = NewKeysDirectory();
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

        var protector = new LocalFileKeySecretProtector(dir);

        var signing = IdentityCertificateStore.EnsureCertificates(
            dir, IdentityCertificateStore.SigningRole, "CN=S", Lifetime, RenewBefore, now, protector).Single();
        var encryption = IdentityCertificateStore.EnsureCertificates(
            dir, IdentityCertificateStore.EncryptionRole, "CN=E", Lifetime, RenewBefore, now, protector).Single();

        Assert.NotEqual(signing.Thumbprint, encryption.Thumbprint);

        // Re-resolving each role must return its own certificate, not the other's.
        Assert.Equal(signing.Thumbprint, IdentityCertificateStore.EnsureCertificates(
            dir, IdentityCertificateStore.SigningRole, "CN=S", Lifetime, RenewBefore, now, protector).Single().Thumbprint);
        Assert.Equal(encryption.Thumbprint, IdentityCertificateStore.EnsureCertificates(
            dir, IdentityCertificateStore.EncryptionRole, "CN=E", Lifetime, RenewBefore, now, protector).Single().Thumbprint);
    }

    [Fact]
    public void RejectsARenewalWindowThatWouldMakeEveryCertificateImmediatelyStale()
    {
        var dir = NewKeysDirectory();

        // renewBefore >= lifetime means a certificate is due for replacement the moment it is
        // created, so every start would mint another key and sign everyone out.
        Assert.Throws<ArgumentOutOfRangeException>(() => IdentityCertificateStore.EnsureCertificates(
            dir, IdentityCertificateStore.SigningRole, "CN=Test", TimeSpan.FromDays(30),
            TimeSpan.FromDays(30), DateTimeOffset.UtcNow, new LocalFileKeySecretProtector(dir)));
    }

    public void Dispose()
    {
        foreach (var dir in _tempDirectories)
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
        }
    }
}
