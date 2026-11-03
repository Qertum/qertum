using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
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
internal sealed class SecretProtectorXmlEncryptor : IXmlEncryptor, IXmlDecryptor
{
    private readonly ISecretProtector protector;

    public SecretProtectorXmlEncryptor(ISecretProtector protector) => this.protector = protector;

    /// <summary>
    /// What Data Protection calls to build the decryptor named in a key file: it activates the type with a constructor
    /// taking <see cref="IServiceProvider"/>, or a parameterless one.
    /// </summary>
    public SecretProtectorXmlEncryptor(IServiceProvider services) : this(services.GetRequiredService<ISecretProtector>()) { }

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
    /// Encrypts the Data Protection key ring's own XML files with <paramref name="protector"/>. Data Protection takes its
    /// encryptor from <see cref="KeyManagementOptions.XmlEncryptor"/> only; an <c>IXmlEncryptor</c> registered as a
    /// service is ignored, which left every key file in plain text until 1.0.0-rc4. Decrypting activates
    /// <see cref="SecretProtectorXmlEncryptor"/> from the service provider by the type name written into each file, so
    /// the protector is registered as a service as well.
    /// </summary>
    public static IDataProtectionBuilder ProtectKeysWithSecretProtector(
        this IDataProtectionBuilder builder, ISecretProtector protector)
    {
        builder.Services.AddSingleton(protector);
        builder.Services.Configure<KeyManagementOptions>(options => options.XmlEncryptor = new SecretProtectorXmlEncryptor(protector));
        return builder;
    }
}
