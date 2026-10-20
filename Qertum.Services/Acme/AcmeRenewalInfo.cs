using System.Buffers.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;

namespace Qertum.Services.Acme;

/// <summary>
/// ACME Renewal Information (RFC 9773): the certificate identifier a client sends and the window the server suggests.
/// Pure: no database, no clock of its own.
/// </summary>
public static class AcmeRenewalInfo
{
    /// <summary>Seconds in the <c>Retry-After</c> header: how long a client may reuse an answer before asking again.</summary>
    public const int RetryAfterSeconds = 6 * 60 * 60;

    private static readonly TimeSpan MaxWindow = TimeSpan.FromDays(1);
    private static readonly TimeSpan ImmediateSpan = TimeSpan.FromHours(1);

    /// <summary>
    /// The identifier of a certificate: <c>base64url(authority key identifier)</c>, a dot, <c>base64url(serial)</c> where the
    /// serial is the DER INTEGER contents (so a leading zero octet when the high bit is set). Null when the certificate has no
    /// authority key identifier, which the identifier cannot be built without.
    /// </summary>
    public static string? CertIdFor(X509Certificate certificate)
    {
        var keyId = AuthorityKeyIdOf(certificate);
        return keyId is null
            ? null
            : $"{Base64Url.EncodeToString(keyId)}.{Base64Url.EncodeToString(certificate.SerialNumber.ToByteArray())}";
    }

    /// <summary>
    /// Splits an identifier into the authority key identifier and the upper-case hex serial the database stores
    /// (<c>SerialNumber.ToString(16)</c>). False for anything that is not strictly two unpadded base64url parts with a positive
    /// serial of at most 20 octets (RFC 5280).
    /// </summary>
    public static bool TryParseCertId(string? certId, out byte[] authorityKeyId, out string serialHex)
    {
        authorityKeyId = [];
        serialHex = "";
        if (string.IsNullOrEmpty(certId))
            return false;
        var parts = certId.Split('.');
        if (parts.Length != 2 || !IsUnpaddedBase64Url(parts[0]) || !IsUnpaddedBase64Url(parts[1]))
            return false;

        var keyId = Base64Url.DecodeFromChars(parts[0]);
        var serial = Base64Url.DecodeFromChars(parts[1]);
        if (keyId.Length == 0 || serial.Length is 0 or > 20 || (serial[0] & 0x80) != 0)
            return false;

        authorityKeyId = keyId;
        serialHex = new BigInteger(1, serial).ToString(16).ToUpperInvariant();
        return true;
    }

    // Base64Url.IsValid accepts '=' padding; the RFC's identifier has none.
    private static bool IsUnpaddedBase64Url(string value) => !value.Contains('=') && Base64Url.IsValid(value);

    /// <summary>The authority key identifier octets of a certificate; null when it has none.</summary>
    public static byte[]? AuthorityKeyIdOf(X509Certificate certificate)
    {
        var raw = certificate.GetExtensionValue(X509Extensions.AuthorityKeyIdentifier);
        return raw is null
            ? null
            : AuthorityKeyIdentifier.GetInstance(Asn1Object.FromByteArray(raw.GetOctets())).KeyIdentifier?.GetOctets();
    }

    /// <summary>
    /// The window in which the client should renew. <paramref name="renewNow"/> (revoked, expired, its issuer retired) gives a
    /// window that has already ended, which the RFC tells a client to treat as "renew immediately". Otherwise the window starts
    /// <paramref name="renewDaysBeforeExpiry"/> before expiry, but never earlier than half way through the lifetime (a short-lived
    /// certificate must not be told to renew the moment it is issued), and lasts a day at most so clients spread out.
    /// </summary>
    public static (DateTime Start, DateTime End) SuggestedWindow(
        DateTime validFromUtc, DateTime validToUtc, bool renewNow, int renewDaysBeforeExpiry, DateTime nowUtc)
    {
        if (renewNow || validToUtc <= nowUtc)
            return (nowUtc - ImmediateSpan, nowUtc);

        var lead = TimeSpan.FromDays(renewDaysBeforeExpiry);
        var half = (validToUtc - validFromUtc) / 2;
        if (lead > half)
            lead = half;
        var start = validToUtc - lead;
        var end = start + MaxWindow;
        return (start, end > validToUtc ? validToUtc : end);
    }
}
