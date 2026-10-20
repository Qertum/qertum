namespace Qertum.Services;

/// <summary>
/// Holds the shared directory path where the CA root key and certificate are stored.
/// Both ApiService and QueueConsumer must resolve this to the same path so they
/// operate on the same CA keypair and Data Protection key ring.
/// </summary>
public sealed class CaDataOptions
{
    /// <summary>
    /// Absolute path to the directory that contains <c>ca.key</c> and <c>ca.pem</c>.
    /// </summary>
    public string Directory { get; init; } = string.Empty;
}
