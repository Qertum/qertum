using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;

namespace Qertum.Services.Acme;

public sealed class JwsParsedRequest
{
    /// <summary>Decoded payload as a JSON document. Null for POST-as-GET (empty payload "").</summary>
    public JsonDocument? Payload { get; init; }

    /// <summary>Resolved account. Null only during new-account (JWK mode).</summary>
    public AcmeAccount? Account { get; init; }

    /// <summary>JWK thumbprint of the key that signed this request.</summary>
    public string JwkThumbprint { get; init; } = string.Empty;

    /// <summary>The raw JWK JSON from the protected header (jwk mode only).</summary>
    public string? EmbeddedJwk { get; init; }
}

/// <summary>
/// Parses and verifies ACME JWS requests (application/jose+json).
/// Verifies: nonce consumption, URL binding, and JWS signature.
/// </summary>
public sealed class JwsRequestParser(
    IAcmeNonceService nonceService,
    CertificateRequestDbContext db)
{
    private static readonly HashSet<string> AllowedAlgorithms =
        ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"];

    public async Task<JwsParsedRequest> ParseAsync(HttpRequest request, CancellationToken ct = default)
    {
        var body = await EnrollmentPayloadLimits.ReadUtf8Async(request, EnrollmentPayloadLimits.AcmeBodyBytes, ct);

        using var doc = JsonDocument.Parse(body);
        var root = doc.RootElement;

        var protectedB64 = root.GetProperty("protected").GetString()
            ?? throw new AcmeException("malformed", "Missing 'protected' field.");
        var payloadB64 = root.GetProperty("payload").GetString()
            ?? throw new AcmeException("malformed", "Missing 'payload' field.");
        var signatureB64 = root.GetProperty("signature").GetString()
            ?? throw new AcmeException("malformed", "Missing 'signature' field.");

        var protectedBytes = EnrollmentPayloadLimits.DecodeBase64(protectedB64, EnrollmentPayloadLimits.ProtectedHeaderBytes);
        var sigBytes = EnrollmentPayloadLimits.DecodeBase64(signatureB64, EnrollmentPayloadLimits.SignatureBytes);
        var payloadBytes = string.IsNullOrEmpty(payloadB64)
            ? null
            : EnrollmentPayloadLimits.DecodeBase64(payloadB64, EnrollmentPayloadLimits.DecodedPayloadBytes);

        using var headerDoc = JsonDocument.Parse(protectedBytes);
        var header = headerDoc.RootElement;

        // Validate alg
        var alg = header.GetProperty("alg").GetString()
            ?? throw new AcmeException("malformed", "Missing 'alg' in protected header.");
        if (!AllowedAlgorithms.Contains(alg))
            throw new AcmeException("badSignatureAlgorithm", $"Algorithm '{alg}' is not supported.");

        // Validate nonce
        if (!header.TryGetProperty("nonce", out var nonceEl) || string.IsNullOrEmpty(nonceEl.GetString()))
            throw new AcmeException("badNonce", "Missing nonce in protected header.");
        var nonce = nonceEl.GetString()!;
        if (!await nonceService.ConsumeAsync(nonce, ct))
            throw new AcmeException("badNonce", "Nonce is invalid or already used.");

        // Validate url — must match the request URL
        if (!header.TryGetProperty("url", out var urlEl))
            throw new AcmeException("malformed", "Missing 'url' in protected header.");
        var claimedUrl = urlEl.GetString() ?? string.Empty;
        var actualUrl = $"{request.Scheme}://{request.Host}{request.Path}{request.QueryString}";
        if (!string.Equals(claimedUrl, actualUrl, StringComparison.OrdinalIgnoreCase))
            throw new AcmeException("malformed", $"URL mismatch: got '{claimedUrl}', expected '{actualUrl}'.");

        // Determine key: jwk (new-account) or kid (everything else)
        var hasJwk = header.TryGetProperty("jwk", out var jwkEl);
        var hasKid = header.TryGetProperty("kid", out var kidEl);

        if (hasJwk == hasKid)
            throw new AcmeException("malformed", "Exactly one of 'jwk' or 'kid' must be present.");

        string jwkJson;
        string thumbprint;
        AcmeAccount? account = null;
        string? embeddedJwk = null;

        if (hasJwk)
        {
            jwkJson = jwkEl.ToString();
            embeddedJwk = jwkJson;
            thumbprint = JwkConverter.ComputeThumbprint(jwkJson);
        }
        else
        {
            // kid is the account URL, e.g. https://host/acme/account/{id}
            var kid = kidEl.GetString() ?? throw new AcmeException("malformed", "Empty 'kid'.");
            if (!TryExtractAccountId(kid, out var accountId))
                throw new AcmeException("accountDoesNotExist", "Cannot resolve account from kid.");

            account = await db.AcmeAccounts.FindAsync([accountId], ct)
                ?? throw new AcmeException("accountDoesNotExist", "Account not found.");
            if (account.Status != "valid")
                throw new AcmeException("unauthorized", "Account is not valid.");

            jwkJson = account.PublicKeyJwk;
            thumbprint = account.JwkThumbprint;
        }

        // Verify signature
        var signingInput = Encoding.ASCII.GetBytes($"{protectedB64}.{payloadB64}");
        VerifySignature(alg, jwkJson, signingInput, sigBytes);

        // Decode payload (empty string "" = POST-as-GET)
        JsonDocument? payload = payloadBytes is null
            ? null
            : JsonDocument.Parse(payloadBytes);

        return new JwsParsedRequest
        {
            Payload = payload,
            Account = account,
            JwkThumbprint = thumbprint,
            EmbeddedJwk = embeddedJwk
        };
    }

    /// <summary>
    /// Verifies the inner JWS of a key-change request (RFC 8555 §7.3.5). The inner object is signed
    /// by the <em>new</em> account key, which is why it carries a <c>jwk</c> rather than a <c>kid</c>,
    /// and why it is not replay-protected by a nonce: the outer JWS already consumed one, and the
    /// inner signature is bound to this request by its <c>url</c> alone.
    /// </summary>
    /// <returns>The inner payload, the new key's JWK JSON, and that key's thumbprint.</returns>
    public static (JsonDocument Payload, string JwkJson, string Thumbprint) ParseInnerJws(
        JsonElement inner, string expectedUrl)
    {
        if (inner.ValueKind != JsonValueKind.Object)
            throw new AcmeException("malformed", "Inner JWS must be a JSON object.");

        var protectedB64 = GetRequiredString(inner, "protected");
        var payloadB64 = GetRequiredString(inner, "payload");
        var signatureB64 = GetRequiredString(inner, "signature");
        var payloadBytes = EnrollmentPayloadLimits.DecodeBase64(payloadB64, EnrollmentPayloadLimits.DecodedPayloadBytes);
        var signatureBytes = EnrollmentPayloadLimits.DecodeBase64(signatureB64, EnrollmentPayloadLimits.SignatureBytes);

        using var headerDoc = JsonDocument.Parse(EnrollmentPayloadLimits.DecodeBase64(protectedB64, EnrollmentPayloadLimits.ProtectedHeaderBytes));
        var header = headerDoc.RootElement;

        var alg = header.TryGetProperty("alg", out var algEl) ? algEl.GetString() : null;
        if (alg is null || !AllowedAlgorithms.Contains(alg))
            throw new AcmeException("badSignatureAlgorithm", $"Algorithm '{alg}' is not supported.");

        // The inner JWS proves possession of the new key, so it must present that key directly. A
        // kid would name an existing account instead, which proves nothing about the new key.
        if (header.TryGetProperty("kid", out _))
            throw new AcmeException("malformed", "Inner JWS must not contain 'kid'.");
        if (!header.TryGetProperty("jwk", out var jwkEl))
            throw new AcmeException("malformed", "Inner JWS must contain 'jwk'.");

        // Binding the inner signature to the same URL is what stops it being lifted out and replayed
        // against a different endpoint.
        var claimedUrl = header.TryGetProperty("url", out var urlEl) ? urlEl.GetString() : null;
        if (!string.Equals(claimedUrl, expectedUrl, StringComparison.OrdinalIgnoreCase))
            throw new AcmeException("malformed", $"Inner JWS URL mismatch: got '{claimedUrl}', expected '{expectedUrl}'.");

        var jwkJson = jwkEl.ToString();
        VerifySignature(alg, jwkJson, Encoding.ASCII.GetBytes($"{protectedB64}.{payloadB64}"),
            signatureBytes);

        if (string.IsNullOrEmpty(payloadB64))
            throw new AcmeException("malformed", "Inner JWS payload must not be empty.");

        return (JsonDocument.Parse(payloadBytes),
                jwkJson,
                JwkConverter.ComputeThumbprint(jwkJson));
    }

    private static string GetRequiredString(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.GetString() is { } text
            ? text
            : throw new AcmeException("malformed", $"Inner JWS is missing '{name}'.");

    private static void VerifySignature(string alg, string jwkJson, byte[] signingInput, byte[] signature)
    {
        using var key = JwkConverter.ImportPublicKey(jwkJson);

        bool valid;
        switch (key)
        {
            case ECDsa ecdsa:
            {
                var hash = alg switch
                {
                    "ES256" => HashAlgorithmName.SHA256,
                    "ES384" => HashAlgorithmName.SHA384,
                    "ES512" => HashAlgorithmName.SHA512,
                    _ => throw new AcmeException("badSignatureAlgorithm", $"Algorithm '{alg}' does not match EC key.")
                };
                // ACME uses IEEE P1363 format (raw r||s), not DER
                valid = ecdsa.VerifyData(signingInput, signature, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
                break;
            }
            case RSA rsa:
            {
                (HashAlgorithmName hash, RSASignaturePadding padding) = alg switch
                {
                    "RS256" => (HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
                    "RS384" => (HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1),
                    "RS512" => (HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1),
                    "PS256" => (HashAlgorithmName.SHA256, RSASignaturePadding.Pss),
                    "PS384" => (HashAlgorithmName.SHA384, RSASignaturePadding.Pss),
                    "PS512" => (HashAlgorithmName.SHA512, RSASignaturePadding.Pss),
                    _ => throw new AcmeException("badSignatureAlgorithm", $"Algorithm '{alg}' does not match RSA key.")
                };
                valid = rsa.VerifyData(signingInput, signature, hash, padding);
                break;
            }
            default:
                throw new AcmeException("badSignatureAlgorithm", "Unsupported key type.");
        }

        if (!valid)
            throw new AcmeException("unauthorized", "JWS signature verification failed.");
    }

    private static bool TryExtractAccountId(string kid, out Guid id)
    {
        // kid format: https://host/acme/account/{guid}
        var lastSlash = kid.LastIndexOf('/');
        if (lastSlash >= 0) return Guid.TryParse(kid[(lastSlash + 1)..], out id);

        id = Guid.Empty;
        return false;
    }
}

/// <summary>ACME protocol error that maps to an RFC 7807 problem response.</summary>
public sealed class AcmeException(string errorType, string detail) : Exception(detail)
{
    /// <summary>ACME error sub-type, e.g. "badNonce", "malformed", "unauthorized".</summary>
    public string ErrorType { get; } = errorType;
}
