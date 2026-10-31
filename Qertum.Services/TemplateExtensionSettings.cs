using System.Text.Json;
using System.Text.RegularExpressions;

namespace Qertum.Services;

/// <summary>The extension settings of a certificate template, read from its four JSON fields.</summary>
public sealed record TemplateExtensions(
    IReadOnlyList<string> KeyUsages,
    IReadOnlyList<string> ExtendedKeyUsages,
    IReadOnlyList<string> SanTypes,
    IReadOnlyList<CustomExtension> CustomExtensions);

/// <summary>
/// The one reader of a template's <c>KeyUsagesJson</c>, <c>ExtendedKeyUsagesJson</c>,
/// <c>SanTypesJson</c> and <c>CustomExtensionsJson</c>. The save validator refuses what this cannot
/// read, and issuance refuses a stored template it cannot read (one saved before the validator),
/// so an extension is never dropped silently: a template without its EKU issues certificates that
/// are valid for any purpose.
/// </summary>
public static partial class TemplateExtensionSettings
{
    /// <summary>Key-usage names the algorithm strategies map (case-sensitive).</summary>
    public static readonly IReadOnlySet<string> KeyUsageNames = new HashSet<string>(StringComparer.Ordinal)
    {
        "DigitalSignature", "NonRepudiation", "KeyEncipherment", "KeyAgreement", "DataEncipherment",
        "KeyCertSign", "CrlSign", "EncipherOnly", "DecipherOnly"
    };

    /// <summary>Subject alternative name types the generator writes (case-sensitive).</summary>
    public static readonly IReadOnlySet<string> SanTypeNames = new HashSet<string>(StringComparer.Ordinal)
    {
        "dns", "ip", "email", "upn"
    };

    // The X.509 certificate extension arc (id-ce). Qertum writes those extensions itself; a custom
    // one there would duplicate or contradict them (a basic-constraints value among them).
    private const string X509ExtensionArc = "2.5.29.";

    private const string NotAStringArray = "Must be a JSON array of strings, for example [] or [\"a\",\"b\"].";

    // Dotted decimal, first arc 0-2, no leading zeros, at least two arcs.
    [GeneratedRegex(@"^[0-2]\.(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*))*$")]
    private static partial Regex OidPattern();

    /// <summary>Reads a stored template; throws naming the template and the field when one cannot be read.</summary>
    public static TemplateExtensions Read(CertificateTemplate template)
    {
        return new TemplateExtensions(
            Require(ReadKeyUsages(template.KeyUsagesJson, out var e1), e1, nameof(template.KeyUsagesJson)),
            Require(ReadExtendedKeyUsages(template.ExtendedKeyUsagesJson, out var e2), e2, nameof(template.ExtendedKeyUsagesJson)),
            Require(ReadSanTypes(template.SanTypesJson, out var e3), e3, nameof(template.SanTypesJson)),
            Require(ReadCustomExtensions(template.CustomExtensionsJson, out var e4), e4, nameof(template.CustomExtensionsJson)));

        T Require<T>(T? value, string? error, string field) where T : class =>
            value ?? throw new InvalidOperationException(
                $"Template '{template.TypeKey}' has an unreadable {field}: {error} Fix the template and submit the request again.");
    }

    /// <summary>Key-usage names, or null with the reason in <paramref name="error"/>.</summary>
    public static IReadOnlyList<string>? ReadKeyUsages(string? json, out string? error) =>
        ReadNames(json, KeyUsageNames, "key usage", out error);

    /// <summary>SAN type names, or null with the reason in <paramref name="error"/>.</summary>
    public static IReadOnlyList<string>? ReadSanTypes(string? json, out string? error) =>
        ReadNames(json, SanTypeNames, "SAN type", out error);

    /// <summary>Extended key usage OIDs, or null with the reason in <paramref name="error"/>.</summary>
    public static IReadOnlyList<string>? ReadExtendedKeyUsages(string? json, out string? error)
    {
        var values = ReadStrings(json);
        error = values is null ? NotAStringArray
            : values.FirstOrDefault(v => !OidPattern().IsMatch(v)) is { } bad
                ? $"'{bad}' is not an OID in dotted form (for example 1.3.6.1.5.5.7.3.1)."
                : Duplicate(values);
        return error is null ? values : null;
    }

    /// <summary>Custom extensions (null or blank = none), or null with the reason in <paramref name="error"/>.</summary>
    public static IReadOnlyList<CustomExtension>? ReadCustomExtensions(string? json, out string? error)
    {
        error = null;
        if (string.IsNullOrWhiteSpace(json)) return [];

        List<CustomExtension?>? items;
        try { items = JsonSerializer.Deserialize<List<CustomExtension?>>(json, AppJsonOptions.Default); }
        catch (JsonException) { items = null; }
        if (items is null)
        {
            error = "Must be a JSON array of {\"oid\", \"value\", \"critical\"} objects.";
            return null;
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in items)
        {
            error = item is null || string.IsNullOrWhiteSpace(item.Oid) || string.IsNullOrWhiteSpace(item.Value)
                    ? "Every custom extension needs an oid and a non-empty value."
                : !OidPattern().IsMatch(item.Oid) ? $"'{item.Oid}' is not an OID in dotted form."
                : item.Oid.StartsWith(X509ExtensionArc, StringComparison.Ordinal)
                    ? $"'{item.Oid}' is a standard X.509 extension (2.5.29.*), which Qertum sets itself."
                : !seen.Add(item.Oid) ? $"'{item.Oid}' is listed twice."
                : null;
            if (error is not null) return null;
        }
        return [.. items.Select(i => i!)];
    }

    private static IReadOnlyList<string>? ReadNames(string? json, IReadOnlySet<string> known, string kind, out string? error)
    {
        var values = ReadStrings(json);
        error = values is null ? NotAStringArray
            : values.FirstOrDefault(v => !known.Contains(v)) is { } bad
                ? $"'{bad}' is not a {kind}; use one of {string.Join(", ", known)}."
                : Duplicate(values);
        return error is null ? values : null;
    }

    private static List<string>? ReadStrings(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try
        {
            var values = JsonSerializer.Deserialize<List<string?>>(json, AppJsonOptions.Default);
            return values is null || values.Any(v => v is null) ? null : [.. values.Select(v => v!)];
        }
        catch (JsonException) { return null; }
    }

    private static string? Duplicate(List<string> values) =>
        values.GroupBy(v => v, StringComparer.Ordinal).FirstOrDefault(g => g.Count() > 1) is { } twice
            ? $"'{twice.Key}' is listed twice."
            : null;
}
