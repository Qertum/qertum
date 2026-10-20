using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;

namespace Qertum.Services;

public class EvaluatedCertificateProperty
{
    public string Name { get; init; } = string.Empty;
    public string Value { get; init; } = string.Empty;
    public bool IsLongText { get; init; }
}

public static class CertificatePropertyEvaluator
{
    public static List<EvaluatedCertificateProperty> EvaluateProperties(X509Certificate2 certificate, ILogger? logger = null)
    {
        var result = new List<EvaluatedCertificateProperty>();

        var properties = certificate.GetType().GetProperties(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance)
                .OrderBy(p => p.Name).ToList();

        foreach (var prop in properties)
        {
            string? displayValue;
            try
            {
                var value = prop.GetValue(certificate);
                if (value == null) continue;

                if (value is X509ExtensionCollection) continue;

                displayValue = value switch
                {
                    PublicKey pk => $"{pk.Oid.FriendlyName} ({GetPublicKeyInfo(certificate)})",
                    DateTime dt => dt.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'"),
                    Oid oid => oid.FriendlyName ?? oid.Value ?? "Unknown",
                    X500DistinguishedName dn => dn.Name,
                    byte[] bytes => BitConverter.ToString(bytes).Replace("-", " "),
                    ReadOnlyMemory<byte> rom => BitConverter.ToString(rom.ToArray()).Replace("-", " "),
                    _ => value.ToString()
                };
            }
            catch (Exception ex)
            {
                if (logger is not null && logger.IsEnabled(LogLevel.Debug))
                    logger.LogDebug(ex, "Failed to evaluate certificate property {PropertyName}", prop.Name);
                continue;
            }

            if (!string.IsNullOrWhiteSpace(displayValue))
            {
                result.Add(new EvaluatedCertificateProperty
                {
                    Name = prop.Name,
                    Value = displayValue,
                    IsLongText = prop.Name is "RawData" or "RawDataMemory"
                });
            }
        }

        return result;
    }

    private static string GetPublicKeyInfo(X509Certificate2 certificate)
    {
        try
        {
            var rsa = certificate.GetRSAPublicKey();
            if (rsa != null) return $"RSA ({rsa.KeySize} bits)";
            
            var ecdsa = certificate.GetECDsaPublicKey();
            if (ecdsa != null) return $"ECDSA ({ecdsa.KeySize} bits)";
        }
        catch 
        { 
            // Return fallback if key parsing fails 
        }

        return certificate.PublicKey.Oid.FriendlyName ?? "Unknown";
    }
}
