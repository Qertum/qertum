using Microsoft.EntityFrameworkCore;

namespace Qertum.Services.Issuers;

internal static class IssuerNames
{
    /// <summary><paramref name="wanted"/>, or <c>"wanted (n)"</c> for the first n no issuer uses yet.</summary>
    public static async Task<string> UniqueAsync(CertificateRequestDbContext db, string wanted, CancellationToken ct)
    {
        var name = wanted;
        for (var n = 2; await db.Issuers.AnyAsync(i => i.Name == name, ct); n++)
            name = $"{wanted} ({n})";
        return name;
    }
}
