using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace Qertum.Services.Acme;

/// <summary>Outcome of an address check, carrying the reason when the address is denied.</summary>
public readonly record struct AddressDecision(bool Allowed, string? DenyReason)
{
    public static AddressDecision Allow() => new(true, null);
    public static AddressDecision Deny(string reason) => new(false, reason);
}

/// <summary>
/// Decides whether an ACME http-01 challenge may connect to a resolved address.
/// </summary>
public interface IAcmeAddressPolicy
{
    /// <summary>
    /// Evaluates one resolved address against the operator-configured allowlist.
    /// </summary>
    /// <param name="address">The address the connection would actually use.</param>
    /// <param name="host">The hostname it was resolved from, for the message only.</param>
    /// <param name="allowedNetworksJson">
    /// <see cref="CaSettings.AcmeChallengeAllowedNetworksJson"/>. Null or empty denies everything.
    /// </param>
    AddressDecision Evaluate(IPAddress address, string host, string? allowedNetworksJson);
}

public sealed class AcmeAddressPolicy(ILogger<AcmeAddressPolicy> logger) : IAcmeAddressPolicy
{
    /// <summary>
    /// Message shown when no allowlist has been configured. Named explicitly rather than surfacing a
    /// bare connection failure, because after upgrading this is the expected state and an operator
    /// needs to know where to go.
    /// </summary>
    public const string NoNetworksConfigured =
        "No allowed networks are configured. Add one under Settings before ACME challenges can be validated.";

    /// <summary>Maximum number of CIDR entries accepted in the allowlist.</summary>
    public const int MaxEntries = 50;

    // Link-local, including the cloud instance-metadata address. Denied unconditionally: metadata is
    // never a legitimate challenge target, and an operator who enters 0.0.0.0/0 must not thereby hand
    // out instance credentials over HTTP.
    private static readonly IPNetwork Ipv4LinkLocal = new(IPAddress.Parse("169.254.0.0"), 16);
    private static readonly IPNetwork Ipv6LinkLocal = new(IPAddress.Parse("fe80::"), 10);

    // A public catch-all must not implicitly grant access to local or special-purpose networks.
    // Private enrollment remains possible when an operator lists a range wholly inside one of these networks.
    private static readonly IPNetwork[] ExplicitNetworks =
    [
        IPNetwork.Parse("0.0.0.0/8"), IPNetwork.Parse("10.0.0.0/8"), IPNetwork.Parse("100.64.0.0/10"),
        IPNetwork.Parse("127.0.0.0/8"), IPNetwork.Parse("172.16.0.0/12"), IPNetwork.Parse("192.0.0.0/24"),
        IPNetwork.Parse("192.0.2.0/24"), IPNetwork.Parse("192.168.0.0/16"), IPNetwork.Parse("198.18.0.0/15"),
        IPNetwork.Parse("198.51.100.0/24"), IPNetwork.Parse("203.0.113.0/24"),
        IPNetwork.Parse("::1/128"), IPNetwork.Parse("::/96"), IPNetwork.Parse("64:ff9b::/96"),
        IPNetwork.Parse("64:ff9b:1::/48"), IPNetwork.Parse("100::/64"), IPNetwork.Parse("2001::/32"),
        IPNetwork.Parse("2001:db8::/32"), IPNetwork.Parse("2002::/16"), IPNetwork.Parse("fc00::/7"), IPNetwork.Parse("fec0::/10")
    ];

    public AddressDecision Evaluate(IPAddress address, string host, string? allowedNetworksJson)
    {
        ArgumentNullException.ThrowIfNull(address);

        // Compare v4-mapped v6 addresses (::ffff:10.0.0.1) as the v4 address they represent, so an
        // operator's "10.0.0.0/8" entry behaves the same regardless of how the resolver reports it.
        var candidate = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

        if (IsLinkLocal(candidate))
            return AddressDecision.Deny(
                $"Address {candidate} for host '{host}' is link-local and is never permitted.");

        var networks = ParseNetworks(allowedNetworksJson);
        if (networks.Count == 0)
            return AddressDecision.Deny(NoNetworksConfigured);

        if (candidate.Equals(IPAddress.Any) || candidate.Equals(IPAddress.IPv6Any)
            || candidate.IsIPv6Multicast || candidate.GetAddressBytes()[0] >= 224 && candidate.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            return AddressDecision.Deny($"Address {candidate} for host '{host}' is not a unicast challenge target.");

        var explicitNetwork = ExplicitNetworks.Where(network => network.Contains(candidate))
            .OrderByDescending(network => network.PrefixLength).Select(network => (IPNetwork?)network).FirstOrDefault();

        foreach (var network in networks)
        {
            if (network.Contains(candidate))
            {
                if (explicitNetwork is null || network.PrefixLength >= explicitNetwork.Value.PrefixLength
                    && explicitNetwork.Value.Contains(network.BaseAddress))
                    return AddressDecision.Allow();
            }
        }

        return AddressDecision.Deny(
            $"Address {candidate} for host '{host}' is not in the configured allowed networks, or needs an explicit internal network entry.");
    }

    private static bool IsLinkLocal(IPAddress address) =>
        Ipv4LinkLocal.Contains(address) || Ipv6LinkLocal.Contains(address);

    /// <summary>
    /// Parses the stored CIDR list. An unparseable entry matches nothing and is logged, rather than
    /// failing the whole list closed — one typo should not become a total ACME outage. The settings
    /// validator rejects malformed entries on save, so this only arises from a hand-edited database.
    /// </summary>
    private List<IPNetwork> ParseNetworks(string? allowedNetworksJson)
    {
        if (string.IsNullOrWhiteSpace(allowedNetworksJson))
            return [];

        List<string>? entries;
        try
        {
            entries = JsonSerializer.Deserialize<List<string>>(allowedNetworksJson);
        }
        catch (JsonException ex)
        {
            logger.LogWarning(ex, "ACME challenge allowed-networks setting is not valid JSON; treating it as empty.");
            return [];
        }

        if (entries is null)
            return [];

        var networks = new List<IPNetwork>(entries.Count);
        foreach (var entry in entries)
        {
            if (TryParseNetwork(entry, out var network))
                networks.Add(network);
            else
                logger.LogWarning("Ignoring malformed ACME allowed-network entry '{Entry}'.", entry);
        }

        return networks;
    }

    /// <summary>
    /// Parses a CIDR entry. Also accepts a bare address, treating it as a single-host range, since an
    /// operator typing "10.0.0.5" plainly means that one host.
    /// </summary>
    public static bool TryParseNetwork(string? entry, out IPNetwork network)
    {
        network = default;
        if (string.IsNullOrWhiteSpace(entry))
            return false;

        var trimmed = entry.Trim();

        if (IPNetwork.TryParse(trimmed, out network))
            return true;

        if (IPAddress.TryParse(trimmed, out var single))
        {
            network = new IPNetwork(single, single.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? 128 : 32);
            return true;
        }

        return false;
    }
}
