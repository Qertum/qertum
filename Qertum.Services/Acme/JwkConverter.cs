using System.Security.Cryptography;
using System.Text.Json;

namespace Qertum.Services.Acme;

/// <summary>Converts JWK JSON objects to BCL ECDsa / RSA key instances and computes RFC 7638 thumbprints.</summary>
public static class JwkConverter
{
    /// <summary>
    /// Imports a JWK public key JSON string into an ECDsa or RSA key.
    /// Returns the key as an <see cref="AsymmetricAlgorithm"/> (cast to ECDsa or RSA as needed).
    /// </summary>
    public static AsymmetricAlgorithm ImportPublicKey(string jwkJson)
    {
        EnrollmentPayloadLimits.CheckUtf8(jwkJson, EnrollmentPayloadLimits.JwkBytes);
        using var doc = JsonDocument.Parse(jwkJson);
        var root = doc.RootElement;
        var kty = root.GetProperty("kty").GetString()
            ?? throw new ArgumentException("JWK missing 'kty'.");

        return kty switch
        {
            "EC" => ImportEcKey(root),
            "RSA" => ImportRsaKey(root),
            _ => throw new NotSupportedException($"Unsupported JWK key type: {kty}")
        };
    }

    /// <summary>Computes the RFC 7638 JWK thumbprint (SHA-256, base64url) for the given JWK JSON.</summary>
    public static string ComputeThumbprint(string jwkJson)
    {
        EnrollmentPayloadLimits.CheckUtf8(jwkJson, EnrollmentPayloadLimits.JwkBytes);
        using var doc = JsonDocument.Parse(jwkJson);
        var root = doc.RootElement;
        var kty = root.GetProperty("kty").GetString()
            ?? throw new ArgumentException("JWK missing 'kty'.");

        // RFC 7638: only the required members, sorted lexicographically, no whitespace.
        var canonical = kty switch
        {
            "EC" => $$"""{"crv":"{{root.GetProperty("crv").GetString()}}","kty":"EC","x":"{{root.GetProperty("x").GetString()}}","y":"{{root.GetProperty("y").GetString()}}"}""",
            "RSA" => $$"""{"e":"{{root.GetProperty("e").GetString()}}","kty":"RSA","n":"{{root.GetProperty("n").GetString()}}"}""",
            _ => throw new NotSupportedException($"Unsupported JWK key type: {kty}")
        };

        var hash = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(canonical));
        return Base64UrlEncode(hash);
    }

    private static ECDsa ImportEcKey(JsonElement root)
    {
        var crv = root.GetProperty("crv").GetString();
        var x = Base64UrlDecode(root.GetProperty("x").GetString()!);
        var y = Base64UrlDecode(root.GetProperty("y").GetString()!);

        var curve = crv switch
        {
            "P-256" => ECCurve.NamedCurves.nistP256,
            "P-384" => ECCurve.NamedCurves.nistP384,
            "P-521" => ECCurve.NamedCurves.nistP521,
            _ => throw new NotSupportedException($"Unsupported EC curve: {crv}")
        };

        var ecParams = new ECParameters
        {
            Curve = curve,
            Q = new ECPoint { X = x, Y = y }
        };

        var ecdsa = ECDsa.Create();
        ecdsa.ImportParameters(ecParams);
        return ecdsa;
    }

    private static RSA ImportRsaKey(JsonElement root)
    {
        var n = Base64UrlDecode(root.GetProperty("n").GetString()!);
        var e = Base64UrlDecode(root.GetProperty("e").GetString()!);

        var rsaParams = new RSAParameters { Modulus = n, Exponent = e };
        var rsa = RSA.Create();
        rsa.ImportParameters(rsaParams);
        return rsa;
    }

    public static string Base64UrlEncode(byte[] input) => Base64UrlText.Encode(input);

    public static byte[] Base64UrlDecode(string input) => Base64UrlText.Decode(input);
}
