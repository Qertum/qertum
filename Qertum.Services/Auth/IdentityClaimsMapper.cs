using System.Security.Claims;
using System.Text.Json;

namespace Qertum.Services.Auth;

/// <summary>
/// Configuration-driven <see cref="IIdentityClaimsMapper"/>. Reads the claim types named in
/// <see cref="IdentityAuthenticationOptions"/>, supporting three shapes seen across providers:
/// repeated claims, a single space-delimited value, and a dotted path into a JSON-valued claim.
/// Claim types containing ':' (URIs like http://schemas.../role, or namespaced identifiers like custom:profile)
/// are always treated as literal claim types. Only simple non-namespaced claim types with a single '.'
/// are parsed as nested paths (e.g., realm_access.roles).
/// </summary>
public sealed class IdentityClaimsMapper : IIdentityClaimsMapper
{
    private readonly IdentityAuthenticationOptions _options;

    public IdentityClaimsMapper(IdentityAuthenticationOptions options)
    {
        _options = options;
    }

    public IReadOnlyCollection<string> GetRoles(ClaimsPrincipal principal)
    {
        var values = ReadClaimValues(principal, _options.RoleClaimType);

        // Fall back to the framework's standard role claim type. ASP.NET Core maps some
        // inbound claims to ClaimTypes.Role, and Qertum's own IdentityService emits "role".
        if (values.Count == 0)
        {
            values = ReadClaimValues(principal, ClaimTypes.Role);
        }

        return Deduplicate(values);
    }

    public IReadOnlyCollection<string> GetScopes(ClaimsPrincipal principal)
    {
        var values = ReadClaimValues(principal, _options.ScopeClaimType);
        return Deduplicate(values.SelectMany(SplitSpaceDelimited));
    }

    public bool IsAdmin(ClaimsPrincipal principal) =>
        GetRoles(principal).Contains(AppRoles.Admin, StringComparer.OrdinalIgnoreCase);

    public string GetName(ClaimsPrincipal principal)
    {
        var configuredClaimType = _options.NameClaimType;
        if (!string.IsNullOrWhiteSpace(configuredClaimType))
        {
            var configured = principal.FindFirst(configuredClaimType)?.Value;
            if (!string.IsNullOrWhiteSpace(configured))
                return configured;
        }

        return principal.FindFirst("preferred_username")?.Value
            ?? principal.FindFirst("name")?.Value
            ?? principal.FindFirst("sub")?.Value
            ?? "unknown";
    }

    public string? GetSubject(ClaimsPrincipal principal)
    {
        // MapInboundClaims is disabled (see AuthenticationServiceCollectionExtensions), so "sub"
        // survives as a literal claim type. ClaimTypes.NameIdentifier is checked as a fallback for
        // principals built by a handler that does apply the inbound claim-type map.
        var subject = principal.FindFirst("sub")?.Value
            ?? principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        return string.IsNullOrWhiteSpace(subject) ? null : subject;
    }

    /// <summary>
    /// Reads values for a claim type. A claim type containing ':' is treated as a namespaced identifier
    /// or URI (e.g., http://schemas.../role or custom:profile) and is always treated as a literal claim type.
    /// Only simple claim types without ':' and containing exactly one '.' are parsed as dotted JSON paths,
    /// for example "realm_access.roles".
    /// </summary>
    private static List<string> ReadClaimValues(ClaimsPrincipal principal, string claimType)
    {
        // Claim types containing ':' are namespaced identifiers or URIs; never dot-split them.
        // JSON dotted paths never contain colons, so this is a reliable discriminator.
        if (!claimType.Contains(':'))
        {
            var separatorIndex = claimType.IndexOf('.');
            var lastDotIndex = claimType.LastIndexOf('.');
            // Only treat as nested path if there's exactly one dot
            if (separatorIndex > 0 && separatorIndex == lastDotIndex && separatorIndex < claimType.Length - 1)
            {
                var outerType = claimType[..separatorIndex];
                var innerProperty = claimType[(separatorIndex + 1)..];
                return ReadNestedJsonValues(principal, outerType, innerProperty);
            }
        }

        return principal.Claims
            .Where(c => string.Equals(c.Type, claimType, StringComparison.Ordinal))
            .Select(c => c.Value)
            .ToList();
    }

    private static List<string> ReadNestedJsonValues(
        ClaimsPrincipal principal, string outerType, string innerProperty)
    {
        var results = new List<string>();

        foreach (var claim in principal.Claims.Where(
            c => string.Equals(c.Type, outerType, StringComparison.Ordinal)))
        {
            JsonElement root;
            try
            {
                using var document = JsonDocument.Parse(claim.Value);
                root = document.RootElement.Clone();
            }
            catch (JsonException)
            {
                // A provider may emit a plain string under this claim type. Treat it as
                // absent rather than failing the whole request.
                continue;
            }

            if (root.ValueKind != JsonValueKind.Object ||
                !root.TryGetProperty(innerProperty, out var inner))
            {
                continue;
            }

            switch (inner.ValueKind)
            {
                case JsonValueKind.Array:
                    results.AddRange(inner.EnumerateArray()
                        .Where(e => e.ValueKind == JsonValueKind.String)
                        .Select(e => e.GetString()!));
                    break;
                case JsonValueKind.String:
                    results.Add(inner.GetString()!);
                    break;
            }
        }

        return results;
    }

    private static IEnumerable<string> SplitSpaceDelimited(string value) =>
        value.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private static IReadOnlyCollection<string> Deduplicate(IEnumerable<string> values) =>
        values
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
}
