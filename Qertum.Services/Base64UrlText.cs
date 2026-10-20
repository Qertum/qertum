namespace Qertum.Services;

/// <summary>
/// Decoding and encoding for the base64url alphabet used by ACME (RFC 8555 / JWS) and, on the
/// decode side, by EST (RFC 7030).
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Decode"/> is deliberately lenient about the alphabet: it maps <c>-</c> and <c>_</c>
/// onto <c>+</c> and <c>/</c> and then decodes, which means input already in the *standard*
/// base64 alphabet passes through untouched and decodes correctly. That is not an accident and
/// must not be "modernized" into <c>System.Buffers.Text.Base64Url</c>: EST's
/// <c>/simpleenroll</c> and <c>/simplereenroll</c> carry a standard-base64 PKCS#10 body per
/// RFC 7030 §4.2.1, so <c>+</c> and <c>/</c> are expected there and a strict base64url decoder
/// would reject essentially every real EST CSR. Padding is optional on input; it is recomputed.
/// </para>
/// <para>
/// <see cref="Encode"/> emits strict, unpadded base64url — the only form ACME accepts on the
/// wire.
/// </para>
/// </remarks>
public static class Base64UrlText
{
    /// <summary>Decodes base64url, also accepting the standard base64 alphabet and optional padding.</summary>
    public static byte[] Decode(string input)
    {
        // Whitespace is not part of the alphabet; counting it would add padding that is already there.
        var s = string.Concat(input.Where(c => !char.IsWhiteSpace(c))).Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4) { case 2: s += "=="; break; case 3: s += "="; break; }
        return Convert.FromBase64String(s);
    }

    /// <summary>Encodes as unpadded base64url.</summary>
    public static string Encode(byte[] input) =>
        Convert.ToBase64String(input)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}
