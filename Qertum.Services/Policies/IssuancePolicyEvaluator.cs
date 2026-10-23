using System.Globalization;
using System.Net;
using System.Text.Json;
using Qertum.Services.Acme;

namespace Qertum.Services.Policies;

public interface IIssuancePolicyEvaluator
{
    /// <summary>
    /// Decides whether <paramref name="request"/> may be issued. Pure: never reads the database —
    /// callers load <paramref name="template"/>, its <paramref name="policy"/> and that policy's
    /// <paramref name="publishedVersion"/> and pass them in. <paramref name="requester"/> is non-null
    /// only for role-bearing submissions (REST create, update, create preview); when null the
    /// requester-role rule is skipped. <paramref name="issuerPath"/> is the issuing CA and every CA
    /// above it; null skips the issuer rules. <paramref name="caller"/> is non-null only for human or
    /// protocol submissions; null skips the CA permission rule.
    /// </summary>
    PolicyDecision Evaluate(
        CertificateRequest request,
        CertificateTemplate? template,
        IssuancePolicy? policy,
        IssuancePolicyVersion? publishedVersion,
        CaSettings settings,
        RequesterRoles? requester = null,
        IReadOnlyList<Issuer>? issuerPath = null,
        CallerContext? caller = null);
}

public sealed class IssuancePolicyEvaluator : IIssuancePolicyEvaluator
{
    public PolicyDecision Evaluate(
        CertificateRequest request,
        CertificateTemplate? template,
        IssuancePolicy? policy,
        IssuancePolicyVersion? publishedVersion,
        CaSettings settings,
        RequesterRoles? requester = null,
        IReadOnlyList<Issuer>? issuerPath = null,
        CallerContext? caller = null)
    {
        if (request.Type == WellKnownCertificateTypes.RootCa)
            return PolicyDecision.Unrestricted;

        // Without this a deleted template would let queued requests of its type issue unrestricted.
        if (template is null)
            return Reject(new IssuancePolicyViolation(PolicyRules.Template, request.Type ?? string.Empty,
                $"No certificate template exists for type '{request.Type}'."));

        if (template.IssuancePolicyId is null)
        {
            // Even ungoverned, a request may only shorten its validity: lengthening past the
            // template/global default takes a policy that explicitly allows it. And no template,
            // governed or not, may put a key that cannot sign into a certificate that must.
            var ungoverned = new List<IssuancePolicyViolation>();
            var notes = new List<string>();
            CheckKeyCapability(request, template, ungoverned);
            CheckCaPermission(template, caller, ungoverned);
            if (issuerPath is not null) IssuerPathRule.Check(request, template, ReadProperties(request.PropertiesJson), issuerPath, settings, ungoverned, notes);
            CheckValidity(request, template, settings, publishedVersion: null, ungoverned);
            return ungoverned.Count == 0
                ? notes.Count == 0 ? PolicyDecision.Unrestricted : PolicyDecision.Unrestricted with { Warnings = notes }
                : new PolicyDecision(false, null, null, null, ungoverned) { Warnings = notes };
        }

        // Link validation prevents this; if it happens anyway, fail closed rather than open.
        if (policy is null || publishedVersion is null)
            return Reject(new IssuancePolicyViolation(PolicyRules.Template, template.TypeKey,
                $"Template '{template.TypeKey}' is linked to a policy with no published version."));

        var violations = new List<IssuancePolicyViolation>();
        var warnings = new List<string>();
        var properties = ReadProperties(request.PropertiesJson);

        CheckDnsSuffixes(request, properties, publishedVersion, violations);
        CheckIpRanges(properties, publishedVersion, violations);
        CheckKeyAlgorithm(request, publishedVersion, violations);
        CheckKeyCapability(request, template, violations);
        CheckCaPermission(template, caller, violations);
        CheckKeyCustody(request, policy, publishedVersion, violations);
        CheckValidity(request, template, settings, publishedVersion, violations);
        if (issuerPath is not null) IssuerPathRule.Check(request, template, properties, issuerPath, settings, violations, warnings);

        var rolesListed = RequesterRoleRule.Allowed(publishedVersion).Count > 0;
        string? matchedRole = null;
        if (rolesListed && requester is not null
            && !RequesterRoleRule.Admits(publishedVersion, requester, out matchedRole))
        {
            var held = requester.Roles.Count == 0 ? "(none)" : string.Join(", ", requester.Roles);
            violations.Add(new IssuancePolicyViolation(PolicyRules.RequesterRole, held,
                $"Role(s) '{held}' may not request under policy '{policy.Name}'; allowed: " +
                $"{string.Join(", ", RequesterRoleRule.Allowed(publishedVersion))}."));
        }

        return new PolicyDecision(violations.Count == 0, publishedVersion.Id, policy.Name,
            publishedVersion.VersionNumber, violations)
        {
            MatchedRequesterRole = matchedRole,
            RequesterIsAdmin = rolesListed && requester?.IsAdmin == true,
            RequesterRolesListed = rolesListed,
            Warnings = warnings
        };
    }

    private static PolicyDecision Reject(IssuancePolicyViolation violation) =>
        new(false, null, null, null, [violation]);

    private static void CheckDnsSuffixes(CertificateRequest request, CertificateProperties properties,
        IssuancePolicyVersion version, List<IssuancePolicyViolation> violations)
    {
        var rawSuffixes = ReadList(version.AllowedDnsSuffixesJson);
        if (rawSuffixes.Count == 0) return;

        var suffixes = rawSuffixes.Select(NormalizeDns).OfType<string>().ToList();

        // The CN is checked even when the template does not emit it as a SAN: older relying parties
        // still trust the CN as a host name.
        var names = new[] { request.CommonName }
            .Concat(properties.DnsNames)
            .Where(n => !string.IsNullOrWhiteSpace(n))
            .Distinct(StringComparer.OrdinalIgnoreCase);

        foreach (var name in names)
        {
            if (!IsWithinSuffix(name, suffixes))
                violations.Add(new IssuancePolicyViolation(PolicyRules.DnsSuffix, name,
                    $"'{name}' is not within an allowed DNS suffix ({string.Join(", ", rawSuffixes)})."));
        }
    }

    internal static bool IsWithinSuffix(string name, IReadOnlyList<string> normalizedSuffixes)
    {
        // A wildcard is judged by its base name: *.corp.example.com is inside corp.example.com,
        // *.example.com is not.
        AcmeEndpointMappings.TryParseWildcard(name.Trim(), out var baseName);
        var normalized = NormalizeDns(baseName);
        if (normalized is null || normalized.Contains('*')) return false;

        return normalizedSuffixes.Any(suffix =>
            normalized == suffix || normalized.EndsWith("." + suffix, StringComparison.Ordinal));
    }

    private static void CheckIpRanges(CertificateProperties properties, IssuancePolicyVersion version,
        List<IssuancePolicyViolation> violations)
    {
        var rawRanges = ReadList(version.AllowedIpRangesJson);
        if (rawRanges.Count == 0) return;

        var ranges = new List<IPNetwork>();
        foreach (var entry in rawRanges)
        {
            if (AcmeAddressPolicy.TryParseNetwork(entry, out var network))
                ranges.Add(network);
        }

        foreach (var ip in properties.IpAddresses)
        {
            if (!IPAddress.TryParse(ip, out var address))
            {
                violations.Add(new IssuancePolicyViolation(PolicyRules.IpRange, ip, $"'{ip}' is not a valid IP address."));
                continue;
            }

            if (!ranges.Any(r => r.Contains(address)))
                violations.Add(new IssuancePolicyViolation(PolicyRules.IpRange, ip,
                    $"'{ip}' is not within an allowed IP range ({string.Join(", ", rawRanges)})."));
        }
    }

    private static void CheckKeyAlgorithm(CertificateRequest request, IssuancePolicyVersion version,
        List<IssuancePolicyViolation> violations)
    {
        var allowed = ReadList(version.AllowedKeyAlgorithmsJson);
        if (allowed.Count == 0) return;

        // Same default CreateAsync applies. Hybrid values match by their own canonical name.
        var effective = (request.KeyAlgorithm ?? CertificateKeyAlgorithm.Rsa).ToCanonicalString();
        if (!allowed.Contains(effective, StringComparer.OrdinalIgnoreCase))
            violations.Add(new IssuancePolicyViolation(PolicyRules.KeyAlgorithm, effective,
                $"Key algorithm '{effective}' is not allowed ({string.Join(", ", allowed)})."));
    }

    /// <summary>A CA-capable template needs the <c>certificates.ca</c> permission from a human caller; protocol callers never qualify.</summary>
    private static void CheckCaPermission(CertificateTemplate template, CallerContext? caller,
        List<IssuancePolicyViolation> violations)
    {
        if (caller is null || CaPermissionRule.Admits(template, caller)) return;

        violations.Add(new IssuancePolicyViolation(PolicyRules.CaPermission, template.TypeKey,
            caller.IsProtocol
                ? $"Template '{template.TypeKey}' issues a CA certificate (KeyCertSign); ACME and EST enrollment cannot use it because nobody approves those requests."
                : $"Template '{template.TypeKey}' issues a CA certificate (KeyCertSign); requesting or approving it needs the {AppPermissions.CertificatesCa} permission."));
    }

    /// <summary>
    /// A template asserting <c>KeyCertSign</c> issues a CA certificate, whose key must sign what it
    /// issues. A KEM key cannot (nor can a signing + encryption pair, whose second certificate is ML-KEM), so the certificate would be unusable as the very thing it claims
    /// to be. Checked here rather than in the generator so every enforcement path — create, renew,
    /// update, approval, the consumer's pre-signing check and the preview — refuses it the same way.
    /// </summary>
    private static void CheckKeyCapability(CertificateRequest request, CertificateTemplate template,
        List<IssuancePolicyViolation> violations)
    {
        var algorithm = request.KeyAlgorithm ?? CertificateKeyAlgorithm.Rsa;
        if (algorithm.CanSign()) return;
        if (!CaCapableTemplate.IsCaCapable(template)) return;

        var name = algorithm.ToCanonicalString();
        var reason = algorithm.GetFamily() == AlgorithmFamily.Pair
            ? $"'{name}' issues an encryption-only (ML-KEM) certificate beside its signing certificate, so it cannot be the " +
              $"key of a CA certificate; template '{template.TypeKey}' issues one (KeyCertSign)."
            : $"'{name}' is a key encapsulation key and cannot sign, so it cannot be the key " +
              $"of a CA certificate; template '{template.TypeKey}' issues one (KeyCertSign).";
        violations.Add(new IssuancePolicyViolation(PolicyRules.KeyCapability, name, reason));
    }

    /// <summary>
    /// A policy may insist the requester holds the key. Only a request carrying a CSR proves that:
    /// for any other request the CA generates the key, stores it encrypted and can export it. The
    /// CSR paths are ACME finalize and EST enrollment, since <c>CsrPem</c> is pipeline-only and no
    /// REST, web or CLI submission can set it.
    /// </summary>
    private static void CheckKeyCustody(CertificateRequest request, IssuancePolicy policy,
        IssuancePolicyVersion version, List<IssuancePolicyViolation> violations)
    {
        if (KeyCustodyRule.AdmitsCaGeneratedKey(version)) return;
        if (!string.IsNullOrWhiteSpace(request.CsrPem)) return;

        violations.Add(new IssuancePolicyViolation(PolicyRules.KeyCustody, "ca-generated",
            $"Policy '{policy.Name}' requires a client-generated key: the request must carry a CSR, " +
            "so enrollment has to go through ACME or EST."));
    }

    private static void CheckValidity(CertificateRequest request, CertificateTemplate template, CaSettings settings,
        IssuancePolicyVersion? publishedVersion, List<IssuancePolicyViolation> violations)
    {
        var defaultDays = ValidityDefaults.EffectiveValidityDays(template, settings);
        var days = ValidityDefaults.EffectiveValidityDays(request, template, settings);

        if (publishedVersion?.MaxValidityDays is int max)
        {
            // A ceiling replaces the default as the limit: under it, a request may ask for longer
            // than the template default, which is the only way to lengthen one.
            if (days > max)
                violations.Add(new IssuancePolicyViolation(PolicyRules.MaxValidity,
                    days.ToString(CultureInfo.InvariantCulture),
                    $"Validity of {days} days exceeds the policy maximum of {max} days."));
            return;
        }

        if (request.ValidityDays is int requested && requested > defaultDays)
            violations.Add(new IssuancePolicyViolation(PolicyRules.MaxValidity,
                requested.ToString(CultureInfo.InvariantCulture),
                $"Requested validity of {requested} days exceeds the default of {defaultDays} days; " +
                "no issuance policy allows a longer one."));
    }

    /// <summary>Lowercase A-label form without a trailing dot, or null when the value is not a usable name.</summary>
    internal static string? NormalizeDns(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;

        var trimmed = value.Trim();
        if (trimmed.EndsWith('.')) trimmed = trimmed[..^1];
        if (trimmed.Length == 0) return null;

        try
        {
            return new IdnMapping().GetAscii(trimmed).ToLowerInvariant();
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    internal static IReadOnlyList<string> ReadList(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return [];
        try
        {
            return JsonSerializer.Deserialize<List<string>>(json)?
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .ToList() ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }

    internal static CertificateProperties ReadProperties(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return new CertificateProperties();
        try
        {
            return JsonSerializer.Deserialize<CertificateProperties>(json, AppJsonOptions.Default)
                   ?? new CertificateProperties();
        }
        catch (JsonException)
        {
            // Names in unparseable JSON are not emitted by the generator either; the CN is still checked.
            return new CertificateProperties();
        }
    }
}
