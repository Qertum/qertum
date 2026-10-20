using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Extensions.DependencyInjection;
using Qertum.ServiceDefaults.Secrets;

namespace Qertum.Services.DataProtection;

/// <summary>
/// Adapts <see cref="ISecretProtector"/> to ASP.NET Data Protection's key-ring encryption
/// extension point. The key ring's own XML files are otherwise unencrypted on disk — this is
/// what closes that gap, and by extension protects everything the key ring itself decrypts (the
/// CA private key, webhook secrets, EAB MAC keys), since those flow through the same key ring.
/// </summary>
internal sealed class SecretProtectorXmlEncryptor(ISecretProtector protector) : IXmlEncryptor, IXmlDecryptor
{
    public EncryptedXmlInfo Encrypt(XElement plaintextElement)
    {
        var plaintextBytes = System.Text.Encoding.UTF8.GetBytes(plaintextElement.ToString(SaveOptions.DisableFormatting));
        var ciphertextBytes = protector.Protect(plaintextBytes);

        var encryptedElement = new XElement("encryptedSecret",
            new XAttribute("provider", "Qertum.ISecretProtector"),
            Convert.ToBase64String(ciphertextBytes));

        return new EncryptedXmlInfo(encryptedElement, typeof(SecretProtectorXmlEncryptor));
    }

    public XElement Decrypt(XElement encryptedElement)
    {
        var ciphertextBytes = Convert.FromBase64String(encryptedElement.Value);
        var plaintextBytes = protector.Unprotect(ciphertextBytes);
        return XElement.Parse(System.Text.Encoding.UTF8.GetString(plaintextBytes));
    }
}

public static class DataProtectionBuilderExtensions
{
    /// <summary>
    /// Encrypts the Data Protection key ring's own XML files with <paramref name="protector"/>.
    /// Call after <c>PersistKeysToFileSystem</c> so the encryptor wraps the on-disk persistence
    /// that's already configured.
    /// </summary>
    public static IDataProtectionBuilder ProtectKeysWithSecretProtector(
        this IDataProtectionBuilder builder, ISecretProtector protector)
    {
        var encryptor = new SecretProtectorXmlEncryptor(protector);
        builder.Services.AddSingleton<IXmlEncryptor>(encryptor);
        builder.Services.AddSingleton<IXmlDecryptor>(encryptor);
        return builder;
    }
}
