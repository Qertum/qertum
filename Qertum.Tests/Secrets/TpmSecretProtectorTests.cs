using Qertum.ServiceDefaults.Secrets;

namespace Qertum.Tests.Secrets;

/// <summary>
/// Needs a real or software (swtpm) TPM 2.0 device plus tpm2-tools on PATH. Skipped rather than
/// failed when unavailable — this environment (and most dev machines / CI runners) has neither,
/// same shape as the Docker-gated Aspire integration tests.
/// </summary>
public sealed class TpmSecretProtectorTests : IDisposable
{
    private readonly string _dataDir = Path.Combine(Path.GetTempPath(), "tpm-protector-test-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_dataDir)) Directory.Delete(_dataDir, recursive: true);
    }

    [Fact]
    public void ProtectThenUnprotect_ReturnsTheOriginalBytes()
    {
        if (!TpmSecretProtector.IsAvailable())
        {
            Assert.Skip("No TPM device / tpm2-tools available in this environment.");
            return;
        }

        var protector = new TpmSecretProtector(_dataDir);
        var plaintext = "hello tpm secret"u8.ToArray();

        var ciphertext = protector.Protect(plaintext);
        var roundTripped = protector.Unprotect(ciphertext);

        Assert.Equal(plaintext, roundTripped);
    }

    [Fact]
    public void IsAvailable_ReturnsFalseWithNoTpmToolingInstalled()
    {
        // This assertion only holds in an environment that genuinely lacks tpm2-tools — which is
        // every dev machine and CI runner this repo currently runs on. If this starts failing
        // because tpm2-tools got installed in the image, that's fine: it means the gated test
        // above will finally exercise the real path instead of skipping.
        Assert.False(TpmSecretProtector.IsAvailable());
    }
}
