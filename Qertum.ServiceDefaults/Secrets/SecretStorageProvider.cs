namespace Qertum.ServiceDefaults.Secrets;

/// <summary>Which <see cref="ISecretProtector"/> implementation protects local secret material.</summary>
public enum SecretStorageProvider
{
    /// <summary>Zero-config default: a locally generated file-based wrapping key.</summary>
    LocalFileKey,

    /// <summary>Wrapping key sealed to a TPM 2.0 device.</summary>
    LocalTpm,

    /// <summary>Not implemented — see <see cref="CloudSecretProtectorStub"/>.</summary>
    CloudStub
}
