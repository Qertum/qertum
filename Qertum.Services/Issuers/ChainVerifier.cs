using Org.BouncyCastle.X509;
using Qertum.Services.Crypto;

namespace Qertum.Services.Issuers;

public sealed record ChainResult(IReadOnlyList<X509Certificate>? Path, string? Error);

/// <summary>
/// Builds the path from a CA certificate to a self-signed root out of an unordered bag of
/// certificates, verifying each signature with <see cref="QertumKeyCodec"/> so ML-DSA, SLH-DSA and
/// composite issuers verify too. Order, duplicates and a repeated subject certificate are tolerated.
/// </summary>
public static class ChainVerifier
{
    private const int MaxDepth = 8;

    public static IReadOnlyList<X509Certificate> ReadAll(string pem)
    {
        var certificates = new List<X509Certificate>();
        const string begin = "-----BEGIN CERTIFICATE-----";
        var index = pem.IndexOf(begin, StringComparison.Ordinal);
        while (index >= 0)
        {
            var next = pem.IndexOf(begin, index + begin.Length, StringComparison.Ordinal);
            var block = next < 0 ? pem[index..] : pem[index..next];
            certificates.Add(QertumKeyCodec.ReadCertificatePem(block)
                             ?? throw new ArgumentException("A certificate in the chain could not be parsed."));
            index = next;
        }
        return certificates;
    }

    public static ChainResult Build(X509Certificate subject, IReadOnlyList<X509Certificate> candidates)
    {
        var pool = candidates.Where(c => !c.Equals(subject)).DistinctBy(c => Convert.ToBase64String(c.GetEncoded())).ToList();
        var path = new List<X509Certificate> { subject };
        var current = subject;
        for (var depth = 0; depth < MaxDepth; depth++)
        {
            if (current.SubjectDN.Equivalent(current.IssuerDN) && SignedBy(current, current))
                return new ChainResult(path, null);

            var issuer = pool.FirstOrDefault(c => c.SubjectDN.Equivalent(current.IssuerDN) && SignedBy(current, c));
            if (issuer is null)
                return new ChainResult(null,
                    $"The chain does not reach a self-signed root: no certificate in chainPem signed '{current.SubjectDN}'.");
            path.Add(issuer);
            pool.Remove(issuer);
            current = issuer;
        }
        return new ChainResult(null, $"The chain is longer than {MaxDepth} certificates.");
    }

    private static bool SignedBy(X509Certificate certificate, X509Certificate issuer)
    {
        try { return certificate.IsSignatureValid(QertumKeyCodec.VerifierFor(QertumKeyCodec.PublicKeyOf(issuer))); }
        catch (Exception) { return false; }
    }
}
