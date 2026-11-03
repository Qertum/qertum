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
    public void ProcessesStartingAtOnceOnAnEmptyDirectory_AllUnsealTheSameKey()
    {
        if (!TpmSecretProtector.IsAvailable())
        {
            Assert.Skip("No TPM device / tpm2-tools available in this environment.");
            return;
        }

        // The single container's CA hosts start together; they used to seal a key each over shared temporary file
        // names (two of three crashed in a real run) and could end up with different keys.
        const int instances = 4;
        using var start = new Barrier(instances);
        var protectors = new TpmSecretProtector[instances];
        Parallel.For(0, instances, new ParallelOptions { MaxDegreeOfParallelism = instances }, i =>
        {
            start.SignalAndWait();
            protectors[i] = new TpmSecretProtector(_dataDir);
        });

        var ciphertext = protectors[0].Protect("one key"u8.ToArray());
        foreach (var other in protectors)
            Assert.Equal("one key"u8.ToArray(), other.Unprotect(ciphertext));
    }

    [Fact]
    public void IsAvailable_IsFalseWithoutATpmDevice()
    {
        // On a machine with a TPM (the x86_64 lab host the release check runs on) the round-trip test above covers
        // the available path; this one pins that a machine without a device answers false instead of failing.
        if (File.Exists("/dev/tpmrm0") || File.Exists("/dev/tpm0"))
        {
            Assert.Skip("This machine has a TPM device; ProtectThenUnprotect_ReturnsTheOriginalBytes covers it.");
            return;
        }

        Assert.False(TpmSecretProtector.IsAvailable());
    }
}
