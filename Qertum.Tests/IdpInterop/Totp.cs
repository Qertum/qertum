using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Qertum.Tests.IdpInterop;

/// <summary>RFC 6238 time-based one-time passwords (SHA-1, 6 digits, 30 s) for the headless Keycloak login.</summary>
internal static class Totp
{
    public static string Code(string base32Secret, DateTimeOffset now, int windowOffset = 0)
    {
        var key = DecodeBase32(base32Secret);
        var counter = now.ToUnixTimeSeconds() / 30 + windowOffset;
        Span<byte> message = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(message, counter);
        var hash = HMACSHA1.HashData(key, message);
        var offset = hash[^1] & 0x0F;
        var value = BinaryPrimitives.ReadInt32BigEndian(hash.AsSpan(offset, 4)) & 0x7FFFFFFF;
        return (value % 1_000_000).ToString("D6");
    }

    private static byte[] DecodeBase32(string text)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var bits = 0;
        var buffer = 0;
        var bytes = new List<byte>();
        foreach (var c in text.TrimEnd('=').ToUpperInvariant())
        {
            buffer = (buffer << 5) | alphabet.IndexOf(c);
            bits += 5;
            if (bits >= 8)
            {
                bytes.Add((byte)(buffer >> (bits - 8)));
                bits -= 8;
            }
        }

        return [.. bytes];
    }
}
