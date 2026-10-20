using Qertum.Services.Policies;

namespace Qertum.Services.BulkOperations;

/// <summary>The production <see cref="IBulkItemActions"/>: the existing single-item service methods, unchanged.</summary>
internal sealed class CertificateRequestBulkItemActions(ICertificateRequestService service) : IBulkItemActions
{
    public async Task<bool> RevokeAsync(CertificateRequestId id, string reason, string performedBy, CancellationToken ct) =>
        await service.MarkAsPendingRevocationAsync(id, reason, performedBy, ct) is not null;

    public async Task<CertificateRequestId> RenewAsync(CertificateRequestId id, string performedBy, CallerContext caller, CancellationToken ct)
    {
        var renewal = await service.RenewAsync(id, performedBy, caller, ct)
            ?? throw new InvalidOperationException("The request no longer exists.");
        return renewal.Id;
    }
}
