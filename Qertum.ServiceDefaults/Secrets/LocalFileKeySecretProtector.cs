using System.Security.Cryptography;

namespace Qertum.ServiceDefaults.Secrets;

/// <summary>
/// Default, zero-config secret protector: a randomly generated 256-bit key stored in a file
/// separate from whatever it protects, encrypting with AES-256-GCM. Weaker than
/// <see cref="TpmSecretProtector"/> — the key is only as safe as the filesystem permissions on
/// this one file — but requires no hardware and always works, which is what makes it the default
/// for a fresh install.
/// </summary>
public sealed class LocalFileKeySecretProtector : ISecretProtector
{
    private const int KeySizeBytes = 32; // AES-256
    private const int NonceSizeBytes = 12; // AES-GCM standard nonce size
    private const int TagSizeBytes = 16;

    private readonly byte[] _key;

    public LocalFileKeySecretProtector(string dataDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataDirectory);

        var secretStorageDir = Path.Combine(dataDirectory, "secret-storage");
        Directory.CreateDirectory(secretStorageDir);
        var keyPath = Path.Combine(secretStorageDir, "local.key");

        if (File.Exists(keyPath))
        {
            _key = File.ReadAllBytes(keyPath);
            if (_key.Length != KeySizeBytes)
                throw new InvalidOperationException($"Secret storage key at '{keyPath}' is corrupt (expected {KeySizeBytes} bytes, found {_key.Length}).");
        }
        else
        {
            _key = RandomNumberGenerator.GetBytes(KeySizeBytes);
            File.WriteAllBytes(keyPath, _key);
            TrySetOwnerOnlyPermissions(keyPath);
        }
    }

    public byte[] Protect(byte[] plaintext)
    {
        var nonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSizeBytes];

        using var aesGcm = new AesGcm(_key, TagSizeBytes);
        aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);

        // Layout: nonce || tag || ciphertext — fixed-size prefix makes Unprotect trivial to slice.
        var result = new byte[NonceSizeBytes + TagSizeBytes + ciphertext.Length];
        nonce.CopyTo(result, 0);
        tag.CopyTo(result, NonceSizeBytes);
        ciphertext.CopyTo(result, NonceSizeBytes + TagSizeBytes);
        return result;
    }

    public byte[] Unprotect(byte[] ciphertext)
    {
        if (ciphertext.Length < NonceSizeBytes + TagSizeBytes)
            throw new CryptographicException("Ciphertext is too short to contain a nonce and tag.");

        var nonce = ciphertext.AsSpan(0, NonceSizeBytes);
        var tag = ciphertext.AsSpan(NonceSizeBytes, TagSizeBytes);
        var cipherBytes = ciphertext.AsSpan(NonceSizeBytes + TagSizeBytes);
        var plaintext = new byte[cipherBytes.Length];

        using var aesGcm = new AesGcm(_key, TagSizeBytes);
        aesGcm.Decrypt(nonce, cipherBytes, tag, plaintext);
        return plaintext;
    }

    private static void TrySetOwnerOnlyPermissions(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        // Windows: no direct equivalent without pulling in ACL APIs; the containing directory's
        // ACLs (inherited from the data volume) are the practical protection there.
    }
}
