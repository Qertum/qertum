namespace Qertum.ServiceDefaults.Secrets;

/// <summary>
/// Documents the seam a real cloud provider (Azure Key Vault, AWS Secrets Manager, HashiCorp
/// Vault) plugs into. Selectable in configuration/UI so the option is visible, but not
/// implemented — every call fails loudly rather than silently no-opping, which would be far
/// worse than an error: a caller reading back "protected" bytes that were never actually
/// protected.
/// </summary>
public sealed class CloudSecretProtectorStub : ISecretProtector
{
    private const string Message =
        "Cloud secret storage is not implemented yet. Select a local provider instead.";

    public byte[] Protect(byte[] plaintext) => throw new NotSupportedException(Message);
    public byte[] Unprotect(byte[] ciphertext) => throw new NotSupportedException(Message);
}
