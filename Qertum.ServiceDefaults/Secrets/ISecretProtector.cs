namespace Qertum.ServiceDefaults.Secrets;

/// <summary>
/// Protects arbitrary secret bytes at rest. Implementations differ only in how the underlying
/// wrapping key is stored/derived — the byte-level contract is the same for all of them, which
/// is what lets a consumer (the Data Protection key ring, the IdentityService PFX files) switch
/// providers without touching call sites.
/// </summary>
public interface ISecretProtector
{
    byte[] Protect(byte[] plaintext);
    byte[] Unprotect(byte[] ciphertext);
}
