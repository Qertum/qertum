using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;

namespace Qertum.Services.Acme;

/// <summary>
/// Verifies the <c>externalAccountBinding</c> field of a new-account request (RFC 8555 §7.3.4).
/// </summary>
/// <remarks>
/// The binding is a second JWS inside the new-account payload, MAC-signed with a key the operator
/// issued out of band. Its payload is the account key being registered, so a valid binding says
/// "the holder of credential <c>kid</c> vouches for this specific account key" — which is what makes
/// it useless to replay against a different key.
/// </remarks>
public static class AcmeExternalAccountBinding
{
    /// <summary>MAC algorithms accepted in the binding JWS header.</summary>
    private static readonly HashSet<string> AllowedAlgorithms = ["HS256", "HS384", "HS512"];

    /// <summary>
    /// Verifies the binding and returns the credential it authenticated as. Throws
    /// <see cref="AcmeException"/> when the binding is absent, malformed, or does not verify.
    /// </summary>
    /// <param name="binding">The <c>externalAccountBinding</c> object from the new-account payload.</param>
    /// <param name="accountJwkJson">The account key from the outer JWS header, which the binding must cover.</param>
    /// <param name="newAccountUrl">The new-account URL the binding must be bound to.</param>
    public static async Task<AcmeExternalAccountKey> VerifyAsync(
        JsonElement binding,
        string accountJwkJson,
        string newAccountUrl,
        CertificateRequestDbContext db,
        CancellationToken ct)
    {
        if (binding.ValueKind != JsonValueKind.Object)
            throw new AcmeException("malformed", "externalAccountBinding must be a JSON object.");

        var protectedB64 = GetRequiredString(binding, "protected");
        var payloadB64 = GetRequiredString(binding, "payload");
        var signatureB64 = GetRequiredString(binding, "signature");

        using var headerDoc = JsonDocument.Parse(EnrollmentPayloadLimits.DecodeBase64(
            protectedB64, EnrollmentPayloadLimits.ProtectedHeaderBytes));
        var header = headerDoc.RootElement;

        var alg = header.TryGetProperty("alg", out var algEl) ? algEl.GetString() : null;
        if (alg is null || !AllowedAlgorithms.Contains(alg))
            throw new AcmeException("badSignatureAlgorithm", $"External account binding algorithm '{alg}' is not supported.");

        // §7.3.4 requires the binding JWS to carry no jwk: the key that signs it is the shared MAC
        // key named by kid, and accepting an embedded key would let the client pick its own.
        if (header.TryGetProperty("jwk", out _))
            throw new AcmeException("malformed", "External account binding must not contain 'jwk'.");

        var kid = header.TryGetProperty("kid", out var kidEl) ? kidEl.GetString() : null;
        if (string.IsNullOrEmpty(kid))
            throw new AcmeException("malformed", "External account binding is missing 'kid'.");

        var claimedUrl = header.TryGetProperty("url", out var urlEl) ? urlEl.GetString() : null;
        if (!string.Equals(claimedUrl, newAccountUrl, StringComparison.OrdinalIgnoreCase))
            throw new AcmeException("malformed", "External account binding 'url' does not match the request URL.");

        var credential = await db.AcmeExternalAccountKeys.FirstOrDefaultAsync(k => k.Kid == kid, ct);

        // Same answer for an unknown kid and a disabled one: telling them apart would turn this into
        // an oracle for which credentials exist.
        if (credential is null || !credential.IsEnabled)
            throw new AcmeException("unauthorized", "Unknown or disabled external account key.");

        VerifyMac(alg, credential.MacKey, protectedB64, payloadB64, signatureB64);

        // The binding's payload is the account key it authorises. Without this check a binding
        // captured from one registration would authorise any other key.
        if (!KeysMatch(payloadB64, accountJwkJson))
            throw new AcmeException("malformed", "External account binding does not cover the account key.");

        return credential;
    }

    private static void VerifyMac(string alg, string macKeyB64Url, string protectedB64, string payloadB64, string signatureB64)
    {
        byte[] macKey;
        byte[] signature;
        try
        {
            macKey = JwkConverter.Base64UrlDecode(macKeyB64Url);
            signature = EnrollmentPayloadLimits.DecodeBase64(signatureB64, EnrollmentPayloadLimits.SignatureBytes);
        }
        catch (FormatException)
        {
            throw new AcmeException("malformed", "External account binding signature is not valid base64url.");
        }

        var signingInput = Encoding.ASCII.GetBytes($"{protectedB64}.{payloadB64}");
        var computed = alg switch
        {
            "HS256" => HMACSHA256.HashData(macKey, signingInput),
            "HS384" => HMACSHA384.HashData(macKey, signingInput),
            _ => HMACSHA512.HashData(macKey, signingInput)
        };

        // Fixed-time comparison: a MAC check that returns early leaks how much of a forged signature
        // was correct.
        if (!CryptographicOperations.FixedTimeEquals(computed, signature))
            throw new AcmeException("unauthorized", "External account binding signature is invalid.");
    }

    /// <summary>
    /// Compares the key inside the binding with the account key, by JWK thumbprint (RFC 7638) rather
    /// than by text, so whitespace and member ordering cannot decide whether a binding is accepted.
    /// </summary>
    private static bool KeysMatch(string payloadB64, string accountJwkJson)
    {
        string boundJwkJson;
        try
        {
            boundJwkJson = Encoding.UTF8.GetString(EnrollmentPayloadLimits.DecodeBase64(
                payloadB64, EnrollmentPayloadLimits.JwkBytes));
        }
        catch (FormatException)
        {
            throw new AcmeException("malformed", "External account binding payload is not valid base64url.");
        }

        try
        {
            return string.Equals(
                JwkConverter.ComputeThumbprint(boundJwkJson),
                JwkConverter.ComputeThumbprint(accountJwkJson),
                StringComparison.Ordinal);
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException)
        {
            throw new AcmeException("malformed", "External account binding payload is not a JWK.");
        }
    }

    private static string GetRequiredString(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.GetString() is { } text
            ? text
            : throw new AcmeException("malformed", $"External account binding is missing '{name}'.");
}
