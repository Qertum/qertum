using Microsoft.EntityFrameworkCore;

namespace Qertum.Services.Policies;

/// <summary>Resolves a stored policy version id to its policy name and number, for audit wording and previews.</summary>
internal static class PolicyVersionLookup
{
    public static async Task<PolicyVersionRef?> FindAsync(CertificateRequestDbContext db, Guid? versionId, CancellationToken ct)
    {
        if (versionId is not { } id) return null;
        var found = await db.IssuancePolicyVersions.AsNoTracking()
            .Where(v => v.Id == id)
            .Join(db.IssuancePolicies.AsNoTracking(), v => v.PolicyId, p => p.Id,
                (v, p) => new { v.VersionNumber, p.Name })
            .FirstOrDefaultAsync(ct);
        return found is null ? null : new PolicyVersionRef(id, found.VersionNumber, found.Name);
    }
}
