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

        // Everything up to the signature check is unauthenticated client input: each shape error is a
        // malformed request, never an exception HandleAcme would have to answer as a server fault.
        using var doc = AcmeJson.ParseObject(body, "request body");
        var root = doc.RootElement;

        var protectedB64 = AcmeJson.RequiredString(root, "protected", "JWS");
        var payloadB64 = AcmeJson.RequiredString(root, "payload", "JWS");
        var signatureB64 = AcmeJson.RequiredString(root, "signature", "JWS");

        var protectedBytes = DecodeBase64(protectedB64, EnrollmentPayloadLimits.ProtectedHeaderBytes, "protected");
        var sigBytes = DecodeBase64(signatureB64, EnrollmentPayloadLimits.SignatureBytes, "signature");
        var payloadBytes = string.IsNullOrEmpty(payloadB64)
            ? null
            : DecodeBase64(payloadB64, EnrollmentPayloadLimits.DecodedPayloadBytes, "payload");

        using var headerDoc = AcmeJson.ParseObject(protectedBytes, "protected header");
        var header = headerDoc.RootElement;

        // Validate alg
        var alg = AcmeJson.OptionalString(header, "alg", "protected header")
            ?? throw new AcmeException("malformed", "Missing 'alg' in protected header.");
        if (!AllowedAlgorithms.Contains(alg))
            throw new AcmeException("badSignatureAlgorithm", $"Algorithm '{alg}' is not supported.");

        // Validate nonce
        var nonce = header.TryGetProperty("nonce", out var nonceEl) && nonceEl.ValueKind == JsonValueKind.String
            ? nonceEl.GetString()
            : null;
        if (string.IsNullOrEmpty(nonce))
            throw new AcmeException("badNonce", "Missing nonce in protected header.");
        if (!await nonceService.ConsumeAsync(nonce, ct))
            throw new AcmeException("badNonce", "Nonce is invalid or already used.");

        // Validate url — must match the request URL
        var claimedUrl = AcmeJson.OptionalString(header, "url", "protected header")
            ?? throw new AcmeException("malformed", "Missing 'url' in protected header.");
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
            // ToString of a JSON string is its unescaped text, which would let a quoted JWK through.
            if (jwkEl.ValueKind != JsonValueKind.Object)
                throw new AcmeException("malformed", "'jwk' must be a JSON object.");
            jwkJson = jwkEl.ToString();
            embeddedJwk = jwkJson;
            thumbprint = JwkConverter.ComputeThumbprint(jwkJson);
        }
        else
        {
            // kid is the account URL, e.g. https://host/acme/account/{id}
            var kid = AcmeJson.OptionalString(header, "kid", "protected header")
                ?? throw new AcmeException("malformed", "Empty 'kid'.");
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

        // Decode payload (empty string "" = POST-as-GET). Every ACME payload is a JSON object, so
        // handlers may call TryGetProperty on it without a kind check.
        JsonDocument? payload = payloadBytes is null
            ? null
            : AcmeJson.ParseObject(payloadBytes, "payload");

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

        var protectedB64 = AcmeJson.RequiredString(inner, "protected", "inner JWS");
        var payloadB64 = AcmeJson.RequiredString(inner, "payload", "inner JWS");
        var signatureB64 = AcmeJson.RequiredString(inner, "signature", "inner JWS");
        var payloadBytes = DecodeBase64(payloadB64, EnrollmentPayloadLimits.DecodedPayloadBytes, "inner payload");
        var signatureBytes = DecodeBase64(signatureB64, EnrollmentPayloadLimits.SignatureBytes, "inner signature");

        using var headerDoc = AcmeJson.ParseObject(
            DecodeBase64(protectedB64, EnrollmentPayloadLimits.ProtectedHeaderBytes, "inner protected header"),
            "inner protected header");
        var header = headerDoc.RootElement;

        var alg = AcmeJson.OptionalString(header, "alg", "inner protected header");
        if (alg is null || !AllowedAlgorithms.Contains(alg))
            throw new AcmeException("badSignatureAlgorithm", $"Algorithm '{alg}' is not supported.");

        // The inner JWS proves possession of the new key, so it must present that key directly. A
        // kid would name an existing account instead, which proves nothing about the new key.
        if (header.TryGetProperty("kid", out _))
            throw new AcmeException("malformed", "Inner JWS must not contain 'kid'.");
        if (!header.TryGetProperty("jwk", out var jwkEl))
            throw new AcmeException("malformed", "Inner JWS must contain 'jwk'.");
        if (jwkEl.ValueKind != JsonValueKind.Object)
            throw new AcmeException("malformed", "Inner 'jwk' must be a JSON object.");

        // Binding the inner signature to the same URL is what stops it being lifted out and replayed
        // against a different endpoint.
        var claimedUrl = AcmeJson.OptionalString(header, "url", "inner protected header");
        if (!string.Equals(claimedUrl, expectedUrl, StringComparison.OrdinalIgnoreCase))
            throw new AcmeException("malformed", $"Inner JWS URL mismatch: got '{claimedUrl}', expected '{expectedUrl}'.");

        var jwkJson = jwkEl.ToString();
        VerifySignature(alg, jwkJson, Encoding.ASCII.GetBytes($"{protectedB64}.{payloadB64}"),
            signatureBytes);

        if (string.IsNullOrEmpty(payloadB64))
            throw new AcmeException("malformed", "Inner JWS payload must not be empty.");

        return (AcmeJson.ParseObject(payloadBytes, "inner payload"),
                jwkJson,
                JwkConverter.ComputeThumbprint(jwkJson));
    }

    /// <summary>Decodes a base64url field; text outside the alphabet is the client's error.</summary>
    private static byte[] DecodeBase64(string input, int maxBytes, string field)
    {
        try
        {
            return EnrollmentPayloadLimits.DecodeBase64(input, maxBytes);
        }
        catch (FormatException)
        {
            throw new AcmeException("malformed", $"'{field}' is not valid base64url.");
        }
    }

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
