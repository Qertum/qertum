namespace Qertum.Services;

/// <summary>
/// Bounds on the public, unauthenticated OCSP POST body. A DER OCSP request names a few CertIDs and
/// is well under a kilobyte; the bound only keeps a caller from making the server buffer large bodies.
/// </summary>
public static class OcspRequestLimits
{
    /// <summary>Largest accepted body; anything longer answers 413.</summary>
    public const int MaxBodyBytes = 64 * 1024;

    /// <summary>Reads at most <see cref="MaxBodyBytes"/> + 1 bytes; null when the body is longer.</summary>
    public static async Task<byte[]?> ReadBodyAsync(Stream body, CancellationToken cancellationToken)
    {
        var buffer = new byte[MaxBodyBytes + 1];
        var total = 0;
        int read;
        while (total < buffer.Length && (read = await body.ReadAsync(buffer.AsMemory(total), cancellationToken)) > 0)
            total += read;
        return total > MaxBodyBytes ? null : buffer[..total];
    }
}
