using System.Security.Cryptography;
using Qertum.ServiceDefaults.Secrets;

namespace Qertum.IdentityService.Services;

/// <summary>A provider change applied at startup, for the audit log.</summary>
public sealed record SecretStorageChange(SecretStorageProvider From, SecretStorageProvider To);

/// <summary>
/// Moves the provider's own key files (<c>keys/*.pfx</c>) to the secret-storage provider named by
/// <c>IdentityService:SecretStorageProvider</c>. The CA's Settings → Secret Storage page cannot do
/// this: the identity provider is a separate process, often on its own host and volume, so its
/// choice is deployment configuration read at startup — the same restart that passing a TPM device
/// through already requires.
/// </summary>
public static class IdentitySecretStorageMigration
{
    /// <summary>
    /// Re-encrypts every file in <c>keys/</c> under <paramref name="configured"/> and records it in
    /// <c>secret-storage.json</c>. Returns <see langword="null"/> without touching anything when
    /// <paramref name="configured"/> is null (keep what is stored) or already stored.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Re-encryption failed; <c>keys/</c> and the recorded provider are unchanged.
    /// </exception>
    public static SecretStorageChange? Apply(
        string dataPath,
        SecretStorageProvider? configured,
        Func<SecretStorageProvider, ISecretProtector> createProtector)
    {
        var keysDir = Path.Combine(dataPath, "keys");
        var stagingDir = keysDir + ".migrating";
        var backupDir = keysDir + ".bak";

        // A crash between the two renames below leaves the backup as the only copy.
        if (!Directory.Exists(keysDir) && Directory.Exists(backupDir))
            Directory.Move(backupDir, keysDir);

        var stored = SecretStorageConfig.Read(dataPath);
        if (configured is not { } target || target == stored)
            return null;

        try
        {
            var source = createProtector(stored);
            var destination = createProtector(target);

            if (Directory.Exists(stagingDir)) Directory.Delete(stagingDir, recursive: true);
            Directory.CreateDirectory(stagingDir);

            if (Directory.Exists(keysDir))
            {
                foreach (var file in Directory.EnumerateFiles(keysDir))
                {
                    var bytes = File.ReadAllBytes(file);
                    byte[] plaintext;
                    try
                    {
                        plaintext = source.Unprotect(bytes);
                    }
                    catch (CryptographicException)
                    {
                        // Legacy plaintext PKCS#12, adopted the same way IdentityCertificateStore reads it.
                        plaintext = bytes;
                    }

                    File.WriteAllBytes(Path.Combine(stagingDir, Path.GetFileName(file)), destination.Protect(plaintext));
                }
            }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            if (Directory.Exists(stagingDir)) Directory.Delete(stagingDir, recursive: true);
            throw new InvalidOperationException(
                $"Moving the identity provider's keys from {stored} to {target} failed; nothing was changed. " +
                $"Fix the cause or unset IdentityService:SecretStorageProvider. {ex.Message}", ex);
        }

        if (Directory.Exists(backupDir)) Directory.Delete(backupDir, recursive: true);
        if (Directory.Exists(keysDir)) Directory.Move(keysDir, backupDir);
        Directory.Move(stagingDir, keysDir);
        SecretStorageConfig.Write(dataPath, target);
        if (Directory.Exists(backupDir)) Directory.Delete(backupDir, recursive: true);

        return new SecretStorageChange(stored, target);
    }
}
