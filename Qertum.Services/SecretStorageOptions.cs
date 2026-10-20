namespace Qertum.Services;

/// <summary>
/// The shared directory `secret-storage.json`, the local-file-key/TPM material, and (indirectly,
/// via <c>DataProtection-Keys/</c> beside it) the Data Protection key ring all live under. Same
/// directory all three of ApiService/QueueConsumer/AcmeService resolve to via the shared
/// connection string, mirroring <see cref="CaDataOptions"/>.
/// </summary>
public sealed class SecretStorageOptions
{
    public string DataDirectory { get; init; } = string.Empty;
}
