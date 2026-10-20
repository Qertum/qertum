using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Qertum.Services;
using Qertum.Services.DataProtection;
using Qertum.ServiceDefaults.Secrets;

namespace Qertum.Tests;

/// <summary>
/// Reproduces the real deployment topology: ApiService and QueueConsumer are separate processes,
/// each with their own <see cref="ICertificateGenerator"/> instance and their own
/// <see cref="IDataProtectionProvider"/>, sharing only the filesystem (CaData + DataProtection-Keys
/// directories) — unlike every other test in this project, which uses one in-process instance for
/// both "sides". This is the one test that can catch a bug that only exists across that boundary.
/// </summary>
public sealed class CaOnboardingCrossProcessTests
{
    [Fact]
    public void ConsumerGeneratesCa_ApiServiceInstanceSeesItImmediately()
    {
        var tempDir = Directory.CreateTempSubdirectory("qertum-ca-test-");
        try
        {
            var caDataOptions = new CaDataOptions { Directory = tempDir.FullName };
            var keysDir = Path.Combine(tempDir.FullName, "DataProtection-Keys");
            Directory.CreateDirectory(keysDir);

            // Two independent DI containers, each with their own IDataProtectionProvider AND their
            // own ISecretProtector instance persisting to the same directory — the exact pipeline
            // ServiceCollectionExtensions.AddCustomCaServices wires up (PersistKeysToFileSystem +
            // ProtectKeysWithSecretProtector), not the bare AddDataProtection() every other test
            // uses. This is what two separate processes actually look like.
            var consumerGenerator = BuildGenerator(tempDir.FullName, keysDir, caDataOptions);
            var apiServiceGenerator = BuildGenerator(tempDir.FullName, keysDir, caDataOptions);

            Assert.False(consumerGenerator.IsInitialized);
            Assert.False(apiServiceGenerator.IsInitialized);

            consumerGenerator.GenerateCa(new GenerateCaRequest
            {
                CommonName = "Test Root CA",
                KeyAlgorithm = CertificateKeyAlgorithm.EcdsaP256
            });

            Assert.True(consumerGenerator.IsInitialized);
            Assert.True(apiServiceGenerator.IsInitialized);
        }
        finally
        {
            tempDir.Delete(recursive: true);
        }
    }

    private static ICertificateGenerator BuildGenerator(string sharedDataDirectory, string keysDir, CaDataOptions caDataOptions)
    {
        var secretProtector = SecretProtectorFactory.Create(sharedDataDirectory);

        var services = new ServiceCollection();
        services.AddDataProtection()
            .PersistKeysToFileSystem(new DirectoryInfo(keysDir))
            .SetApplicationName("Qertum")
            .ProtectKeysWithSecretProtector(secretProtector);
        services.AddLogging();
        var provider = services.BuildServiceProvider();

        return new CertificateGenerator(
            provider.GetRequiredService<IDataProtectionProvider>(),
            caDataOptions,
            NullLogger<CertificateGenerator>.Instance);
    }
}
