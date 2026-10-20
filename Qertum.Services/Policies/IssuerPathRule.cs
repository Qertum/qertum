using System.Net;
using Qertum.Services.Acme;
using Qertum.Services.Issuers;

namespace Qertum.Services.Policies;

/// <summary>
/// What the issuing CA's own certificate allows: RFC 5280 path length and name constraints of every
/// CA on the path. Checked here, before signing, so a request a relying party would reject is
/// refused with a reason instead of issued broken.
/// </summary>
internal static class IssuerPathRule
{
    public static void Check(CertificateRequest request, CertificateTemplate template, CertificateProperties properties,
        IReadOnlyList<Issuer> path, List<IssuancePolicyViolation> violations)
    {
        if (path.Count == 0) return;

        if (CaCapableTemplate.IsCaCapable(template))
        {
            for (var i = 0; i < path.Count; i++)
            {
                // CA certificates that would follow path[i]: those between it and the issuing CA, the
                // issuing CA itself (when i > 0), and the new one — i + 1 in all.
                if (path[i].PathLengthConstraint is int allowed && allowed < i + 1)
                {
                    violations.Add(new IssuancePolicyViolation(PolicyRules.IssuerPathLength, path[i].Name,
                        $"Issuer '{path[i].Name}' allows {allowed} CA certificate(s) below it; a CA certificate issued by " +
                        $"'{path[0].Name}' would be number {i + 1}."));
                    break;
                }
            }
        }

        var dnsNames = new List<string>();
        if (LooksLikeHostName(request.CommonName)) dnsNames.Add(request.CommonName.Trim());
        dnsNames.AddRange(properties.DnsNames.Where(n => !string.IsNullOrWhiteSpace(n)).Select(n => n.Trim()));
        var ips = properties.IpAddresses.Select(ip => IPAddress.TryParse(ip, out var a) ? a : null).OfType<IPAddress>().ToList();

        var reported = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var ca in path)
        {
            var permittedDns = IssuancePolicyEvaluator.ReadList(ca.PermittedDnsSuffixesJson);
            var excludedDns = IssuancePolicyEvaluator.ReadList(ca.ExcludedDnsSuffixesJson);
            foreach (var name in dnsNames.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                var outside = permittedDns.Count > 0 && !permittedDns.Any(s => NameConstraintMatcher.DnsWithin(name, s));
                var excluded = excludedDns.FirstOrDefault(s => NameConstraintMatcher.DnsWithin(name, s));
                if ((outside || excluded is not null) && reported.Add(name))
                    violations.Add(new IssuancePolicyViolation(PolicyRules.IssuerNameConstraints, name, excluded is not null
                        ? $"'{name}' is inside '{excluded}', which issuer '{ca.Name}' excludes."
                        : $"'{name}' is outside the names issuer '{ca.Name}' may certify ({string.Join(", ", permittedDns)})."));
            }

            var permittedIp = IssuancePolicyEvaluator.ReadList(ca.PermittedIpRangesJson);
            var excludedIp = IssuancePolicyEvaluator.ReadList(ca.ExcludedIpRangesJson);
            foreach (var ip in ips)
            {
                var text = ip.ToString();
                var outside = permittedIp.Count > 0 && !permittedIp.Any(r => NameConstraintMatcher.IpWithin(ip, r));
                var excluded = excludedIp.FirstOrDefault(r => NameConstraintMatcher.IpWithin(ip, r));
                if ((outside || excluded is not null) && reported.Add(text))
                    violations.Add(new IssuancePolicyViolation(PolicyRules.IssuerNameConstraints, text, excluded is not null
                        ? $"'{text}' is inside '{excluded}', which issuer '{ca.Name}' excludes."
                        : $"'{text}' is outside the addresses issuer '{ca.Name}' may certify ({string.Join(", ", permittedIp)})."));
            }
        }
    }

    /// <summary>A CN is only a DNS name when it looks like one; "Jane Doe" (S/MIME, client auth) is not constrained.</summary>
    private static bool LooksLikeHostName(string? commonName)
    {
        if (string.IsNullOrWhiteSpace(commonName)) return false;
        AcmeEndpointMappings.TryParseWildcard(commonName.Trim(), out var baseName);
        return baseName.Contains('.') && Uri.CheckHostName(baseName.TrimEnd('.')) == UriHostNameType.Dns;
    }
}
