namespace Qertum.Services.BulkOperations;

/// <summary>Previews, executes, cancels and reads bulk revoke and renew operations.</summary>
public interface IBulkOperationService
{
    /// <summary>Resolves the filter, freezes the eligible set and stores a <see cref="BulkOperationStatus.Previewed"/> operation.</summary>
    /// <exception cref="BulkOperationException">422 for an empty or contradictory filter, a missing revoke reason, nothing eligible or more than <c>MaxItems</c>.</exception>
    Task<BulkOperationPreview> PreviewAsync(PreviewBulkOperationRequest request, BulkActor actor, CancellationToken ct = default);

    /// <summary>Starts a previewed operation. <exception cref="BulkOperationException">404 unknown; 409 not previewed or wrong count; 410 preview expired.</exception></summary>
    Task<BulkOperationView> ExecuteAsync(BulkOperationId id, int confirmCount, BulkActor actor, CancellationToken ct = default);

    /// <summary>Cancels a previewed operation. <exception cref="BulkOperationException">404 unknown; 409 not previewed.</exception></summary>
    Task<BulkOperationView> CancelAsync(BulkOperationId id, BulkActor actor, CancellationToken ct = default);

    /// <summary>One operation, or null if unknown. Access is the caller's to check with <see cref="BulkOperationAccess"/>.</summary>
    Task<BulkOperationView?> GetAsync(BulkOperationId id, CancellationToken ct = default);

    /// <summary>Operations newest first; with <paramref name="creatorSubject"/> only that creator's, with null all.</summary>
    Task<PagedResult<BulkOperationView>> ListAsync(int page, int pageSize, string? creatorSubject, CancellationToken ct = default);

    /// <summary>A page of items, optionally one outcome; null if the operation is unknown.</summary>
    Task<PagedResult<BulkOperationItemView>?> GetItemsAsync(BulkOperationId id, BulkItemOutcome? outcome, int page, int pageSize, CancellationToken ct = default);
}
