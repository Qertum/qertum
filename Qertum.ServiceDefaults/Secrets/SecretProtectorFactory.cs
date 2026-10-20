namespace Qertum.ServiceDefaults.Secrets;

public static class SecretProtectorFactory
{
    /// <summary>The protector for the provider recorded in <paramref name="dataDirectory"/>.</summary>
    public static ISecretProtector Create(string dataDirectory) =>
        Create(dataDirectory, SecretStorageConfig.Read(dataDirectory));

    /// <summary>
    /// The protector for <paramref name="provider"/>, keyed to <paramref name="dataDirectory"/>,
    /// whatever that directory currently records — what a migration needs for its target.
    /// </summary>
    public static ISecretProtector Create(string dataDirectory, SecretStorageProvider provider)
    {
        return provider switch
        {
            SecretStorageProvider.LocalFileKey => new LocalFileKeySecretProtector(dataDirectory),
            SecretStorageProvider.LocalTpm => new TpmSecretProtector(dataDirectory),
            SecretStorageProvider.CloudStub => new CloudSecretProtectorStub(),
            var other => throw new NotSupportedException($"Unknown secret storage provider '{other}'.")
        };
    }
}
