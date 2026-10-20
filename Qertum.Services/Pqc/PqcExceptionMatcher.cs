using Qertum.Services.Policies;

namespace Qertum.Services;

/// <summary>Pure test of whether one exception covers one request. Reuses the policy engine's DNS matching.</summary>
public static class PqcExceptionMatcher
{
    /// <summary>
    /// True when <paramref name="exception"/> is active at <paramref name="nowUtc"/>, names this template
    /// and algorithm family, and covers EVERY DNS name of the request. A request with any non-DNS SAN,
    /// or with no DNS names, never matches, so an extra name cannot ride along on another name's exception.
    /// </summary>
    public static bool Matches(PqcException exception, string? templateTypeKey, CertificateKeyAlgorithm algorithm,
        IReadOnlyList<string> dnsNames, bool hasNonDnsNames, DateTime nowUtc)
    {
        if (exception.RevokedAtUtc is not null || exception.ExpiresAtUtc <= nowUtc) return false;
        if (!string.Equals(exception.TemplateTypeKey, templateTypeKey, StringComparison.Ordinal)) return false;
        if (hasNonDnsNames || dnsNames.Count == 0) return false;

        var family = algorithm.GetFamily();
        var familyMatches = exception.Family switch
        {
            PqcExceptionFamily.Rsa => family == AlgorithmFamily.Rsa,
            PqcExceptionFamily.Ecdsa => family == AlgorithmFamily.Ecdsa,
            _ => false
        };
        if (!familyMatches) return false;

        var suffix = IssuancePolicyEvaluator.NormalizeDns(exception.NamePattern);
        if (suffix is null) return false;
        var suffixes = new[] { suffix };

        return dnsNames.All(name => IssuancePolicyEvaluator.IsWithinSuffix(name, suffixes));
    }
}
