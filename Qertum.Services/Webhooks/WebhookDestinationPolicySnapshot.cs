using System.Net;

namespace Qertum.Services.Webhooks;

/// <summary>An immutable view of the effective destination policy for one delivery attempt.</summary>
public sealed record WebhookDestinationPolicySnapshot(
    bool Initialized,
    WebhookPublicMode PublicMode,
    IReadOnlyList<WebhookDestinationRuleSnapshot> Rules);

/// <summary>One exact origin and its optional allowed IP addresses.</summary>
public sealed record WebhookDestinationRuleSnapshot(
    Guid Id,
    string Source,
    WebhookDestinationRuleKind Kind,
    string Scheme,
    string Host,
    int Port,
    bool Enabled,
    IReadOnlyList<IPAddress> AllowedIpAddresses);

/// <summary>Whether a destination passed the address policy, with a safe failure reason.</summary>
public sealed record WebhookAddressDecision(bool Allowed, string? Reason);
