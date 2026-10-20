using System.Net;
using System.Net.Sockets;

namespace Qertum.Services.Webhooks;

/// <summary>Evaluates all DNS answers against a webhook destination policy.</summary>
public static class WebhookAddressPolicy
{
    internal static bool IsEligibleInternalPin(IPAddress address)
        => !IsAlwaysBlocked(address) && !IsPublic(address);

    /// <summary>Checks an origin and every resolved IP address before a connection is opened.</summary>
    public static WebhookAddressDecision Check(
        WebhookDestinationPolicySnapshot snapshot,
        WebhookDestinationTarget target,
        IReadOnlyList<IPAddress> addresses)
    {
        if (!snapshot.Initialized || addresses.Count == 0)
            return new(false, "Webhook destination policy is unavailable.");
        if (addresses.Any(IsAlwaysBlocked))
            return new(false, "Webhook destination address is blocked.");
        return IsAllowedByOrigin(snapshot, target, addresses)
            ? new(true, null)
            : new(false, "Webhook destination is not allowed by policy.");
    }

    private static bool IsAllowedByOrigin(
        WebhookDestinationPolicySnapshot snapshot, WebhookDestinationTarget target,
        IReadOnlyList<IPAddress> addresses)
    {
        var exactRules = snapshot.Rules.Where(rule => rule.Enabled &&
            rule.Scheme.Equals(target.Scheme, StringComparison.OrdinalIgnoreCase) &&
            rule.Host.Equals(target.Host, StringComparison.OrdinalIgnoreCase) && rule.Port == target.Port).ToList();

        if (addresses.All(IsPublic))
            return snapshot.PublicMode == WebhookPublicMode.AnyPublic ||
                exactRules.Any(rule => rule.Kind == WebhookDestinationRuleKind.Public);

        return addresses.All(ip => !IsPublic(ip)) &&
            exactRules.Any(rule => rule.Kind == WebhookDestinationRuleKind.Internal &&
                addresses.All(ip => rule.AllowedIpAddresses.Any(pin => Normalize(pin).Equals(Normalize(ip)))));
    }

    private static IPAddress Normalize(IPAddress ip) => ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip;

    private static bool IsAlwaysBlocked(IPAddress input)
    {
        var ip = Normalize(input);
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            return b[0] == 0 || b[0] >= 224 || b[0] == 169 && b[1] == 254 ||
                b[0] == 100 && b[1] == 100 && b[2] == 100 && b[3] == 200;
        }

        if (ip.AddressFamily != AddressFamily.InterNetworkV6) return true;
        var bytes = ip.GetAddressBytes();
        return ip.Equals(IPAddress.IPv6None) || ip.Equals(IPAddress.IPv6Any) ||
            ip.IsIPv6LinkLocal || ip.IsIPv6Multicast ||
            bytes[0] == 0xfd && bytes[1] == 0x00 && bytes[2] == 0x0e &&
            bytes[3] == 0xc2 && bytes.Skip(4).Take(10).All(value => value == 0) &&
            bytes[14] == 0x02 && bytes[15] == 0x54;
    }

    private static bool IsPublic(IPAddress input)
    {
        var ip = Normalize(input);
        if (IsAlwaysBlocked(ip)) return false;
        var b = ip.GetAddressBytes();
        if (ip.AddressFamily == AddressFamily.InterNetwork)
            return b[0] != 10 && b[0] != 127 &&
                !(b[0] == 100 && b[1] is >= 64 and <= 127) &&
                !(b[0] == 172 && b[1] is >= 16 and <= 31) &&
                !(b[0] == 192 && (b[1] == 168 || b[1] == 0 || b[1] == 88 && b[2] == 99 || b[1] == 0 && b[2] == 2)) &&
                !(b[0] == 198 && (b[1] is 18 or 19 || b[1] == 51 && b[2] == 100)) &&
                !(b[0] == 203 && b[1] == 0 && b[2] == 113);

        // Only global unicast IPv6 may be public; exclude documentation and tunnels.
        return ip.AddressFamily == AddressFamily.InterNetworkV6 && (b[0] & 0xe0) == 0x20 &&
            !(b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8) &&
            !(b[0] == 0x20 && b[1] == 0x02) &&
            !(b[0] == 0x20 && b[1] == 0x01 && b[2] == 0 && b[3] == 0);
    }
}
