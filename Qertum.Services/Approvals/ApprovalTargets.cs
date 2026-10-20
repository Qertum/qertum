using Microsoft.EntityFrameworkCore;

namespace Qertum.Services.Approvals;

/// <summary>Finds what an approval is about and gives it a readable name.</summary>
internal static class ApprovalTargets
{
    /// <summary>
    /// A GUID target in its one canonical form (lower case, no braces), so the id a requester typed and the id in the URL
    /// are the same string when a grant is claimed. Anything that is not a GUID is returned trimmed.
    /// </summary>
    public static string? Normalize(string? targetId)
    {
        if (string.IsNullOrWhiteSpace(targetId))
            return null;
        var trimmed = targetId.Trim();
        return Guid.TryParse(trimmed, out var id) ? id.ToString("D") : trimmed;
    }

    /// <summary>The target's readable name, or null when it does not exist (or is not a bulk operation of kind revoke).</summary>
    public static async Task<string?> LabelAsync(
        CertificateRequestDbContext db, string operation, string? targetId, CancellationToken cancellationToken)
    {
        if (operation == ApprovalOperations.IssuerCreateIntermediate)
            return "a new intermediate issuer";
        if (!Guid.TryParse(targetId, out var id))
            return null;

        switch (operation)
        {
            case ApprovalOperations.KeyExport:
            case ApprovalOperations.PfxExport:
                return await db.CertificateRequests.AsNoTracking().Where(r => r.Id == new CertificateRequestId(id))
                    .Select(r => r.CommonName).FirstOrDefaultAsync(cancellationToken);
            case ApprovalOperations.BulkRevoke:
                var bulk = await db.BulkOperations.AsNoTracking().Where(o => o.Id == new BulkOperationId(id) && o.Kind == BulkOperationKind.Revoke)
                    .Select(o => new { o.ItemCount }).FirstOrDefaultAsync(cancellationToken);
                return bulk is null ? null : $"bulk revoke of {bulk.ItemCount} certificates";
            case ApprovalOperations.PolicyPublish:
                return await db.IssuancePolicies.AsNoTracking().Where(p => p.Id == new IssuancePolicyId(id))
                    .Select(p => p.Name).FirstOrDefaultAsync(cancellationToken);
            default:
                return await db.Issuers.AsNoTracking().Where(i => i.Id == new IssuerId(id))
                    .Select(i => i.Name).FirstOrDefaultAsync(cancellationToken);
        }
    }
}
