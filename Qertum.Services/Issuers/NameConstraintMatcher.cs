using System.Net;
using Qertum.Services.Acme;
using Qertum.Services.Policies;

namespace Qertum.Services.Issuers;

/// <summary>RFC 5280 §4.2.1.10 matching for the name forms Qertum constrains: DNS names and IP addresses.</summary>
public static class NameConstraintMatcher
{
    /// <summary>
    /// Whether <paramref name="name"/> is <paramref name="suffix"/> or a subdomain of it, on a label
    /// boundary (evilcorp.example is not inside corp.example). A wildcard is judged by its base name.
    /// </summary>
    public static bool DnsWithin(string name, string suffix)
    {
        AcmeEndpointMappings.TryParseWildcard(name.Trim(), out var baseName);
        var normalizedName = IssuancePolicyEvaluator.NormalizeDns(baseName);
        var normalizedSuffix = IssuancePolicyEvaluator.NormalizeDns(suffix);
        if (normalizedName is null || normalizedSuffix is null || normalizedName.Contains('*')) return false;
        return normalizedName == normalizedSuffix || normalizedName.EndsWith("." + normalizedSuffix, StringComparison.Ordinal);
    }

    /// <summary>Whether suffix <paramref name="inner"/> names a subset of <paramref name="outer"/>.</summary>
    public static bool SuffixWithin(string inner, string outer) => DnsWithin(inner, outer);

    public static bool IpWithin(IPAddress address, string cidr) =>
        AcmeAddressPolicy.TryParseNetwork(cidr, out var network) && network.Contains(address);

    /// <summary>Whether range <paramref name="inner"/> lies entirely within <paramref name="outer"/>.</summary>
    public static bool CidrWithin(string inner, string outer) =>
        IPNetwork.TryParse(inner, out var i) && IPNetwork.TryParse(outer, out var o) &&
        i.BaseAddress.AddressFamily == o.BaseAddress.AddressFamily &&
        i.PrefixLength >= o.PrefixLength && o.Contains(i.BaseAddress);
}
