namespace Qertum.Services;

/// <summary>The effective webhook destination mode and visible exact-origin rules.</summary>
public sealed class WebhookDestinationPolicyResponse
{
    /// <summary>The effective public-destination mode.</summary>
    public WebhookPublicMode PublicMode { get; init; }

    /// <summary>Whether API startup completed JSON reconciliation.</summary>
    public bool Initialized { get; init; }

    /// <summary>Current configuration and administrator rules, including disabled rules.</summary>
    public IReadOnlyList<WebhookDestinationRuleResponse> Rules { get; init; } = [];
}

/// <summary>One exact-origin rule visible to an administrator.</summary>
public sealed class WebhookDestinationRuleResponse
{
    /// <summary>Persistent rule identifier.</summary>
    public Guid Id { get; init; }

    /// <summary>Configuration or Admin.</summary>
    public string Source { get; init; } = "";

    /// <summary>Public or internal address class.</summary>
    public WebhookDestinationRuleKind Kind { get; init; }

    /// <summary>HTTP or HTTPS.</summary>
    public string Scheme { get; init; } = "";

    /// <summary>Normalized exact hostname.</summary>
    public string Host { get; init; } = "";

    /// <summary>Effective destination port.</summary>
    public int Port { get; init; }

    /// <summary>Whether this rule currently permits deliveries.</summary>
    public bool Enabled { get; init; }

    /// <summary>Exact pinned IP addresses for an internal rule.</summary>
    public IReadOnlyList<string> AllowedIpAddresses { get; init; } = [];
}

/// <summary>Sets or clears the administrator's override of the JSON public mode.</summary>
public sealed class SetWebhookDestinationModeRequest
{
    /// <summary>AnyPublic, ListedPublic, or null to use JSON configuration.</summary>
    public WebhookPublicMode? PublicMode { get; init; }
}

/// <summary>Creates one administrator-owned exact-origin rule.</summary>
public sealed class SaveWebhookDestinationRuleRequest
{
    /// <summary>Public or internal address class.</summary>
    public WebhookDestinationRuleKind Kind { get; init; }

    /// <summary>HTTP or HTTPS.</summary>
    public string Scheme { get; init; } = "https";

    /// <summary>Exact hostname or IP literal.</summary>
    public string Host { get; init; } = "";

    /// <summary>Effective destination port.</summary>
    public int Port { get; init; } = 443;

    /// <summary>Exact IP pins, required for an internal rule and empty for a public rule.</summary>
    public string[] AllowedIpAddresses { get; init; } = [];
}

/// <summary>Enables or disables a destination rule.</summary>
public sealed class SetWebhookDestinationRuleEnabledRequest
{
    /// <summary>Whether the rule should be enabled.</summary>
    public bool Enabled { get; init; }
}
