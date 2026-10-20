namespace Qertum.Services.Webhooks;

/// <summary>The single row tracking initialization and public-destination mode.</summary>
public sealed class WebhookDestinationPolicyState
{
    /// <summary>Singleton key, always 1.</summary>
    public int Id { get; set; } = 1;

    /// <summary>Whether API startup completed reconciliation.</summary>
    public bool Initialized { get; set; }

    /// <summary>Public mode supplied by JSON configuration.</summary>
    public WebhookPublicMode JsonPublicMode { get; set; } = WebhookPublicMode.AnyPublic;

    /// <summary>Administrator override, when set.</summary>
    public WebhookPublicMode? AdminPublicMode { get; set; }

    /// <summary>UTC time of the last JSON reconciliation.</summary>
    public DateTime? ReconciledAtUtc { get; set; }
}
