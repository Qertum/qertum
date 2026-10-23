namespace Qertum.Services;

/// <summary>Names post-quantum signature OIDs consistently across API, Web, and CLI.</summary>
public static class CertificateSignatureAlgorithms
{
    /// <summary>Canonical algorithm name by signature OID, including composite signatures.</summary>
    public static IReadOnlyDictionary<string, string> PostQuantumSignatureOids { get; } =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["2.16.840.1.101.3.4.3.17"] = "ML-DSA-44",
            ["2.16.840.1.101.3.4.3.18"] = "ML-DSA-65",
            ["2.16.840.1.101.3.4.3.19"] = "ML-DSA-87",
            ["2.16.840.1.101.3.4.3.20"] = "SLH-DSA-SHA2-128S",
            ["2.16.840.1.101.3.4.3.21"] = "SLH-DSA-SHA2-128F",
            ["2.16.840.1.101.3.4.3.22"] = "SLH-DSA-SHA2-192S",
            ["2.16.840.1.101.3.4.3.23"] = "SLH-DSA-SHA2-192F",
            ["2.16.840.1.101.3.4.3.24"] = "SLH-DSA-SHA2-256S",
            ["2.16.840.1.101.3.4.3.25"] = "SLH-DSA-SHA2-256F"
        }
        .Concat(CertificateKeyAlgorithmExtensions.CompositeAlgorithmsByOid
            .Select(pair => KeyValuePair.Create(pair.Key, pair.Value.ToCanonicalString())))
        .ToDictionary(StringComparer.Ordinal);
}
