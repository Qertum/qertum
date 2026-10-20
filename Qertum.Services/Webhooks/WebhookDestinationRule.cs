namespace Qertum.Services.Webhooks;

/// <summary>A stored exact-origin rule from configuration or an administrator.</summary>
public sealed class WebhookDestinationRule
{
    /// <summary>Persistent rule identifier.</summary>
    public Guid Id { get; set; }

    /// <summary>Either Configuration or Admin.</summary>
    public string Source { get; set; } = "Configuration";

    /// <summary>Stable identity of the normalized origin and IP pins.</summary>
    public string StableKey { get; set; } = "";

    /// <summary>The address class this rule permits.</summary>
    public WebhookDestinationRuleKind Kind { get; set; }

    /// <summary>HTTP or HTTPS.</summary>
    public string Scheme { get; set; } = "https";

    /// <summary>Normalized exact hostname.</summary>
    public string Host { get; set; } = "";

    /// <summary>Effective destination port.</summary>
    public int Port { get; set; }

    /// <summary>JSON array of exact normalized IP address strings.</summary>
    public string AllowedIpAddressesJson { get; set; } = "[]";

    /// <summary>Whether the rule still exists in its source.</summary>
    public bool IsPresent { get; set; } = true;

    /// <summary>Whether the rule is enabled by its source.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Administrator's persistent disable override for a configuration rule.</summary>
    public bool AdminDisabled { get; set; }
}
