namespace Qertum.Services;

/// <summary>Generic paginated result container.</summary>
/// <typeparam name="T">The item type returned in this page.</typeparam>
public sealed class PagedResult<T>
{
    /// <summary>Items on the current page.</summary>
    public IReadOnlyList<T> Items { get; init; } = [];
    /// <summary>Total number of items across all pages.</summary>
    public int TotalCount { get; init; }
    /// <summary>Current (1-based) page number.</summary>
    public int Page { get; init; }
    /// <summary>Maximum number of items per page.</summary>
    public int PageSize { get; init; }
    /// <summary>Total number of pages.</summary>
    public int TotalPages => PageSize > 0 ? (int)Math.Ceiling((double)TotalCount / PageSize) : 0;
}
