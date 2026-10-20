namespace Qertum.Services;

/// <summary>The head of one audit chain: the latest sequence number and its hash.</summary>
public sealed class AuditChainHead
{
    /// <summary>The chain (writer) name.</summary>
    public string Writer { get; init; } = string.Empty;

    /// <summary>The latest sequence number found.</summary>
    public long Seq { get; init; }

    /// <summary>The hash of that entry (lowercase hex SHA-256).</summary>
    public string Hash { get; init; } = string.Empty;
}

/// <summary>
/// Every audit chain head at one moment. Kept off-host (the webhook receiver, a saved file), it is what
/// <c>qca audit verify --anchor</c> checks a copied log against.
/// </summary>
public sealed class AuditCheckpoint
{
    /// <summary>When the heads were read (UTC).</summary>
    public DateTime GeneratedAtUtc { get; init; }

    /// <summary>One head per writer found, ordered by writer name; empty when nothing is chained yet.</summary>
    public IReadOnlyList<AuditChainHead> Chains { get; init; } = [];
}
