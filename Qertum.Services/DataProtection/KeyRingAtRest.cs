using System.Xml.Linq;
using Qertum.ServiceDefaults.Secrets;

namespace Qertum.Services.DataProtection;

/// <summary>
/// The CA key ring files (<c>DataProtection-Keys/*.xml</c>) under the secret-storage provider: encrypting the files an
/// older version left in plain text, and moving the ring from one provider to another.
/// </summary>
public static class KeyRingAtRest
{
    private static readonly XNamespace DataProtection = "http://schemas.asp.net/2015/03/dataProtection";
    private static readonly XName RequiresEncryption = DataProtection + "requiresEncryption";
    private static readonly XName EncryptedSecretWrapper = DataProtection + "encryptedSecret";
    // The element SecretProtectorXmlEncryptor writes inside Data Protection's wrapper; it has no namespace.
    private static readonly XName ProtectorPayload = "encryptedSecret";

    /// <summary>
    /// Encrypts every key-file element Data Protection marked as needing encryption but wrote in plain text (all of them
    /// before 1.0.0-rc4, when the encryptor was not wired), the same way Data Protection does when an encryptor is set.
    /// Each file is replaced atomically, so another process reads either the old or the new file, and both decrypt.
    /// Run once by ApiService at start; a second run finds nothing. Returns how many files were rewritten.
    /// </summary>
    public static int EncryptPlainKeyFiles(string keysDirectory, ISecretProtector protector)
    {
        if (!Directory.Exists(keysDirectory)) return 0;
        var encryptor = new SecretProtectorXmlEncryptor(protector);
        var rewritten = 0;
        foreach (var file in Directory.EnumerateFiles(keysDirectory, "*.xml"))
        {
            var xml = XElement.Load(file);
            if (!EncryptMarkedElements(xml, encryptor)) continue;
            var temporary = file + ".tmp-" + Guid.NewGuid().ToString("N");
            xml.Save(temporary);
            File.Move(temporary, file, overwrite: true);
            rewritten++;
        }
        return rewritten;
    }

    /// <summary>
    /// Re-encrypts the key ring under <paramref name="targetProvider"/> and records it as the provider. The target's key
    /// lives in the live data directory (a TPM-sealed blob or <c>local.key</c> under <c>secret-storage/</c>): a target
    /// built anywhere else is deleted with it, and the ring becomes unreadable at the next restart. Files are written to
    /// a staging directory and swapped in only when all of them succeeded; a failure leaves the live ring as it was
    /// (the two renames of the swap are a narrow, non-transactional window; a restart follows the migration anyway).
    /// </summary>
    public static void Migrate(string dataDirectory, SecretStorageProvider targetProvider)
    {
        var source = new SecretProtectorXmlEncryptor(SecretProtectorFactory.Create(dataDirectory));
        var target = new SecretProtectorXmlEncryptor(SecretProtectorFactory.Create(dataDirectory, targetProvider));

        var keysDir = Path.Combine(dataDirectory, "DataProtection-Keys");
        var stagingDir = Path.Combine(dataDirectory, "DataProtection-Keys.migrating");
        var backupDir = Path.Combine(dataDirectory, "DataProtection-Keys.bak");
        // Left behind by versions before 1.0.0-rc4, which built the target protector there.
        var oldStagingConfigDir = Path.Combine(dataDirectory, "secret-storage.migrating");

        if (Directory.Exists(stagingDir)) Directory.Delete(stagingDir, recursive: true);
        Directory.CreateDirectory(stagingDir);

        if (Directory.Exists(keysDir))
        {
            foreach (var file in Directory.EnumerateFiles(keysDir, "*.xml"))
            {
                // Only the protector's payload changes; the key's outer XML (id, dates, descriptor) must stay as it is,
                // or Data Protection can no longer parse the file.
                var xml = XElement.Load(file);
                foreach (var payload in xml.Descendants(ProtectorPayload).ToList())
                    payload.ReplaceWith(target.Encrypt(source.Decrypt(payload)).EncryptedElement);
                EncryptMarkedElements(xml, target);
                xml.Save(Path.Combine(stagingDir, Path.GetFileName(file)));
            }
        }

        if (Directory.Exists(backupDir)) Directory.Delete(backupDir, recursive: true);
        if (Directory.Exists(keysDir))
            Directory.Move(keysDir, backupDir);
        Directory.Move(stagingDir, keysDir);

        SecretStorageConfig.Write(dataDirectory, targetProvider);

        if (Directory.Exists(backupDir)) Directory.Delete(backupDir, recursive: true);
        if (Directory.Exists(oldStagingConfigDir)) Directory.Delete(oldStagingConfigDir, recursive: true);
    }

    private static bool EncryptMarkedElements(XElement xml, SecretProtectorXmlEncryptor encryptor)
    {
        var marked = xml.Descendants()
            .Where(e => string.Equals((string?)e.Attribute(RequiresEncryption), "true", StringComparison.OrdinalIgnoreCase))
            .ToList();
        foreach (var element in marked)
        {
            var info = encryptor.Encrypt(new XElement(element));
            element.ReplaceWith(new XElement(EncryptedSecretWrapper,
                new XAttribute("decryptorType", info.DecryptorType.AssemblyQualifiedName!),
                info.EncryptedElement));
        }
        return marked.Count > 0;
    }
}
