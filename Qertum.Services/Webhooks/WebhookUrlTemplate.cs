using System.Text.RegularExpressions;

namespace Qertum.Services.Webhooks;

/// <summary>
/// Substitutes <c>{field}</c> placeholders in a webhook's target URL. Every token must name a field
/// the webhook's family allows (see <see cref="WebhookEventFields"/>), which is checked when the
/// webhook is saved rather than at delivery time.
/// </summary>
/// <remarks>
/// Substitution runs on the stored URL string. Do not route a template through <see cref="Uri"/>
/// first: <c>Uri.AbsoluteUri</c> percent-encodes the braces, and <c>{event}</c> becomes
/// <c>%7Bevent%7D</c>, which no longer matches a placeholder.
/// </remarks>
internal static partial class WebhookUrlTemplate
{
    /// <summary>Longest substituted value; anything longer is truncated.</summary>
    public const int MaxValueLength = 256;

    /// <summary>Longest resolved URL — the <c>WebhookDelivery.ResolvedUrl</c> column's limit.</summary>
    public const int MaxResolvedUrlLength = 4000;

    /// <summary>Stored marker for an expansion that cannot fit the resolved URL column.</summary>
    public const string OversizedResolvedUrl = "qertum-invalid:resolved-url-overflow";

    [GeneratedRegex(@"\{([A-Za-z][A-Za-z0-9]*)\}", RegexOptions.CultureInvariant)]
    private static partial Regex TokenPattern();

    /// <summary>The distinct placeholder names in <paramref name="url"/>.</summary>
    public static IReadOnlyList<string> ExtractTokens(string url) =>
        TokenPattern().Matches(url ?? string.Empty)
            .Select(m => m.Groups[1].Value)
            .Distinct(StringComparer.Ordinal)
            .ToList();

    /// <summary>
    /// Whether every placeholder in <paramref name="url"/> is a field <paramref name="family"/>
    /// carries. On failure <paramref name="error"/> names the offending tokens and the allowed fields.
    /// </summary>
    public static bool TryValidate(string url, WebhookEventFamily family, out string? error)
    {
        var unknown = ExtractTokens(url)
            .Where(t => !WebhookEventFields.IsKnown(family, t))
            .ToList();

        if (unknown.Count == 0)
        {
            error = null;
            return true;
        }

        var allowed = WebhookEventFields.All(family).OrderBy(f => f, StringComparer.Ordinal);
        error = $"Url references field(s) the {family} family does not carry: {string.Join(", ", unknown)}. " +
                $"Available placeholders: {string.Join(", ", allowed)}.";
        return false;
    }

    /// <summary>
    /// Replaces each known placeholder with its URL-encoded value, truncating each value to
    /// <see cref="MaxValueLength"/>. An oversized result becomes <see cref="OversizedResolvedUrl"/>
    /// so delivery rejects it instead of sending a truncated target. A null or
    /// absent value becomes the empty string; a token that is not in <paramref name="values"/> at all
    /// is left as written, because enqueue must not throw.
    /// </summary>
    public static string Resolve(string url, IReadOnlyDictionary<string, string?> values)
    {
        var resolved = TokenPattern().Replace(url, match =>
        {
            var name = match.Groups[1].Value;
            if (!values.TryGetValue(name, out var value)) return match.Value;
            if (string.IsNullOrEmpty(value)) return string.Empty;

            var trimmed = value.Length > MaxValueLength ? value[..MaxValueLength] : value;
            return Uri.EscapeDataString(trimmed);
        });

        return resolved.Length > MaxResolvedUrlLength ? OversizedResolvedUrl : resolved;
    }
}
