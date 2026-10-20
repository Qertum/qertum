using System.Text;
using Microsoft.AspNetCore.Http;

namespace Qertum.Services;

/// <summary>Byte limits for ACME and EST enrollment input.</summary>
public static class EnrollmentPayloadLimits
{
    /// <summary>Maximum raw ACME JWS body size.</summary>
    public const int AcmeBodyBytes = 128 * 1024;
    /// <summary>Maximum raw EST enrollment body size.</summary>
    public const int EstBodyBytes = 96 * 1024;
    /// <summary>Maximum decoded JWS payload size.</summary>
    public const int DecodedPayloadBytes = 64 * 1024;
    /// <summary>Maximum decoded PKCS#10 CSR size.</summary>
    public const int CsrBytes = 64 * 1024;
    /// <summary>Maximum decoded JWS protected-header size.</summary>
    public const int ProtectedHeaderBytes = 32 * 1024;
    /// <summary>Maximum UTF-8 JWK size.</summary>
    public const int JwkBytes = 16 * 1024;
    /// <summary>Maximum decoded JWS signature size.</summary>
    public const int SignatureBytes = 32 * 1024;

    /// <summary>Reads no more than the declared byte limit plus one byte.</summary>
    public static async Task<string> ReadUtf8Async(HttpRequest request, int maxBytes, CancellationToken ct)
    {
        if (request.ContentLength > maxBytes)
            throw new EnrollmentPayloadTooLargeException();

        var bytes = new byte[maxBytes + 1];
        var count = 0;
        while (count < bytes.Length)
        {
            var read = await request.Body.ReadAsync(bytes.AsMemory(count), ct);
            if (read == 0) break;
            count += read;
        }
        if (count > maxBytes)
            throw new EnrollmentPayloadTooLargeException();
        return Encoding.UTF8.GetString(bytes, 0, count);
    }

    /// <summary>
    /// Removes the line breaks and spaces of RFC 2045 base64, which RFC 7030 clients (libest, globalsign/est)
    /// use for CSR bodies. The text is stored and compared as sent, so it is made canonical on the way in.
    /// </summary>
    public static string WithoutWhitespace(string text) => string.Concat(text.Where(c => !char.IsWhiteSpace(c)));

    /// <summary>Rejects encoded input before decoding and checks the exact decoded size.</summary>
    public static byte[] DecodeBase64(string input, int maxBytes)
    {
        if (input.Length > ((maxBytes + 2) / 3) * 4)
            throw new EnrollmentPayloadTooLargeException();
        var decoded = Base64UrlText.Decode(input);
        if (decoded.Length > maxBytes)
            throw new EnrollmentPayloadTooLargeException();
        return decoded;
    }

    /// <summary>Checks a JWK or other UTF-8 string before cryptographic parsing.</summary>
    public static void CheckUtf8(string input, int maxBytes)
    {
        if (input.Length > maxBytes || Encoding.UTF8.GetByteCount(input) > maxBytes)
            throw new EnrollmentPayloadTooLargeException();
    }
}

/// <summary>Signals that an enrollment input exceeds a protocol limit.</summary>
public sealed class EnrollmentPayloadTooLargeException : Exception;
